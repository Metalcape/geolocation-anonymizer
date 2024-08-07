import shapely
import random
import requests
import osm2geojson
import argparse
from rtree import index
import lzma
import pickle
import bisect
import numpy as np
import os

ADMIN_LV_MIN = 2
ADMIN_LV_MAX = 11

class Region:
    shape: shapely.MultiPolygon | bytes
    name: str
    admin_level: int
    compressed: bool | None
    includes_shape: bool
    def __init__(self, name: str, admin_level: int, shape: shapely.MultiPolygon | None = None, compress=True):
        self.name = name
        self.admin_level = admin_level
        if shape is not None:
            if compress:
                shape_data = pickle.dumps(shape)
                self.shape = lzma.compress(shape_data)
            else:
                self.shape = shape
            self.compressed = compress
            self.includes_shape = True
        else:
            self.compressed = None
            self.includes_shape = False
    
    def boundary(self) -> shapely.MultiPolygon:
        if not self.includes_shape:
            raise AttributeError("The region does not contain shape data.")
        if self.compressed:
            shape = lzma.decompress(self.shape)
            return pickle.loads(shape)
        else:
            return self.shape
    
    def contains_point(self, point: shapely.Point) -> bool:
        if self.includes_shape:
            shape = self.boundary()
            return shape.contains(point)
        else:
            raise AttributeError("The region does not contain shape data.")

        
class Country(Region):
    subregions: dict
    def __init__(self, name: str, shape: shapely.MultiPolygon | None = None, subregions: list[Region] = None, compress=True):
        super().__init__(name, ADMIN_LV_MIN, shape, compress)
        self.subregions = dict()
        for i in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1):
            self.subregions[f'lv_{i}'] = list()
        if subregions is not None:
            self.add_subregions(subregions)
    
    def add_subregions(self, subregions: list):
        for r in subregions:
            self.subregions[f'lv_{r.admin_level}'].append(r)
        for i in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1):
            self.subregions[f'lv_{i}'].sort(key=lambda r: r.name.casefold())
    
    def get_all_subregions(self) -> list[Region]:
        all_subregions = list()
        for i in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1):
            all_subregions += self.subregions[f'lv_{i}']
        return all_subregions
    
    def get_vector_index(self, region: Region) -> int:
        if (region.admin_level <= ADMIN_LV_MIN) or (region.admin_level > ADMIN_LV_MAX):
            raise AttributeError("Administrative level out of range.")
        
        base_index = 0
        for l in range(ADMIN_LV_MIN + 1, region.admin_level + 1):
            if l == region.admin_level:
                i = bisect.bisect_left(self.subregions[f'lv_{l}'], region.name, key=lambda r: r.name)
                if self.subregions[f'lv_{l}'][i].name == region.name:
                    return base_index + i
                else:
                    raise ValueError(f"The subregion at index {base_index + i} should be {region.name} but is actually {self.subregions[f'lv_{l}'][i].name}")
            base_index += len(self.subregions[f'lv_{l}'])
        raise ValueError(f"The vector index for {region.name} was not found")
    
    def get_regions_from_vector(self, vector: np.ndarray) -> list[Region]:
        indices, = np.where(vector == 1)
        regions = list()
        
        base_index = 0
        for l in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1):
            for i in indices:
                if i >= base_index and i < len(self.subregions[f'lv_{l}']) + base_index:
                    regions.append(self.subregions[f'lv_{l}'][i - base_index])
            base_index += len(self.subregions[f'lv_{l}'])
        return regions
    
    def geolocate_as_vector(self, point: shapely.Point):
        all_subregions = self.get_all_subregions()
        location_vector = np.array([0]*len(all_subregions), dtype=np.uint64)
        
        # Build an rtree to search for the point location
        idx = index.Index()
        for i, region in enumerate(all_subregions):
            idx.insert(i, region.boundary().bounds, obj=region)

        # Search for overlapping regions
        candidates = list(idx.intersection(point.bounds, objects=True))
        for c in candidates:
            region = c.object
            if region.contains_point(point):
                ind = self.get_vector_index(region)
                location_vector[ind] = 1
        return location_vector
    
    def serialize(self):
        os.makedirs('./cache', exist_ok=True)
        file_path = f'./cache/{self.name}.pkl'
        
        with open(file_path, 'wb') as file:
            pickle.dump(self, file)
    
    @staticmethod
    def deserialize(name: str):
        file_path = f'./cache/{name}.pkl'
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"No cached data found for {name}.")
        
        with open(file_path, 'rb') as file:
            country = pickle.load(file)
        return country

def regions_query(country_name):
    query = f"""
        [out:json];
        area["name:en"="{country_name}"]["boundary"="administrative"]->.searchArea;
        relation["boundary"="administrative"][admin_level ~ "^[3-9]|1[0-1]$"](area.searchArea);
        out geom;
    """
    return query

def fetch_overpass_data(query):
    overpass_url = "http://overpass-api.de/api/interpreter"
    response = requests.get(overpass_url, params={'data': query})
    response.raise_for_status()
    return response.json()

def shape_obj_to_region(shape_obj: dict, compress=True) -> Region:
    lv = int(shape_obj['properties']['tags']['admin_level'])
    shape = shape_obj['shape']
    try:
        name = shape_obj['properties']['tags']['name:en']
    except KeyError:
        name = shape_obj['properties']['tags']['name']
    return Region(name, lv, shape, compress)

def shape_obj_to_country(shape_obj: dict, compress=True) -> Country:
    try:
        name = shape_obj['properties']['tags']['name:en']
    except KeyError:
        name = shape_obj['properties']['tags']['name']
    shape = shape_obj['shape']
    return Country(name, shape, None, compress)

def find_country(point: shapely.Point) -> Country | None:
    query = f"""
        [out:json];
        (
        relation["boundary"="administrative"]["admin_level"="2"];
        );
        out geom;
    """

    file_path = f'./cache/__countries.pkl'
    if not os.path.exists(file_path):
        overpass_data = fetch_overpass_data(query)
        shape_objects = osm2geojson.json2shapes(overpass_data)
        countries = [shape_obj_to_country(obj) for obj in shape_objects]
        with open(file_path, 'wb') as file:
            pickle.dump(countries, file)
    else: 
        with open(file_path, 'rb') as file:
            countries = pickle.load(file)

    # Build an rtree to search for the point location
    idx = index.Index()
    for i, country in enumerate(countries):
        idx.insert(i, country.boundary().bounds, obj=country)

    # Search for overlapping regions
    candidates = list(idx.intersection(point.bounds, objects=True))
    for c in candidates:
        country = c.object
        if country.contains_point(point):
            return country
  
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a request vector for the anonymizer based on the coordinates passed as arguments."
    )

    parser.add_argument(
        "-lat",
        "--latitude",
        type=float,
        action="store",
        help="latitude of the position between -90 and 90 decimal degrees.",
    )
    parser.add_argument(
        "-lon",
        "--longitude",
        type=float,
        action="store",
        help="longitude of the position between -180 and 180 decimal degrees.",
    )
    parser.add_argument(
        "-r",
        "--random",
        action="count",
        default=0,
        help="use a random pair of coordinates.",
    )

    point = None
    args = parser.parse_args()
    if args.random >= 1:
        point = shapely.Point(random.uniform(-180, 180), random.uniform(-90, 90))  # longitude first
    else:
        if args.latitude is None or args.longitude is None:
            raise SystemExit("Invalid arguments. Use option -h for help.")
        if args.latitude < -90.0 or args.latitude > 90.0:
            raise SystemExit("Latitude must be between -90 and 90.")
        if args.longitude < -180.0 or args.longitude > 180.0:
            raise SystemExit("Latitude must be between -180 and 180.")
        point = shapely.Point(args.longitude, args.latitude)

    country = find_country(point)
    if country is None:
        raise SystemError("The coordinates do not belong to any country's territory.")
    print(f"The point {point.y}, {point.x} is inside: {country.name}")

    # Try to load country data from cache
    try:
        country = Country.deserialize(country.name)
    except FileNotFoundError:
        # Download subregions data
        query = regions_query(country.name)
        overpass_data = fetch_overpass_data(query)
        shape_objects = osm2geojson.json2shapes(overpass_data)
        subregions = [shape_obj_to_region(obj) for obj in shape_objects]
        country.add_subregions(subregions)
        # Save to cache
        country.serialize()  

    # Get the list of regions containing the point
    vector = country.geolocate_as_vector(point)
    containing_regions = country.get_regions_from_vector(vector)
    print('Geolocation vector:')
    print(vector)
    print('List of containing regions:')
    for r in containing_regions:
        print(f'lv = {r.admin_level}, name = {r.name}')

    # Send location vector to server
    
    # Await response from server