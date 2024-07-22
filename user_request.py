import geopy.distance
import shapely
import random
import geopy
import requests
import osm2geojson
import argparse
from rtree import index
import lzma
import pickle
import itertools
import numpy

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
            self.subregions[f'lv_{i}'] = list[Region]
        if subregions is not None:
            for r in subregions:
                self.subregions[f'lv_{r.admin_level}'].append(r)
            for i in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1):
                sorted(self.subregions[f'lv_{i}'], key=lambda r: r.name)
    
    def add_subregions(self, subregions: list[Region], compress=True):
        for r in subregions:
            self.subregions[f'lv_{r.admin_level}'].append(r)
        for i in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1):
            sorted(self.subregions[f'lv_{i}'], key=lambda r: r.name)
    
    def geolocate(self, point: shapely.Point) -> list[Region]:
        # Build an rtree to search for the point location
        idx = index.Index()
        for i, region in enumerate(itertools.chain([subregions[f'lv_{j}'] for j in range(ADMIN_LV_MIN + 1, ADMIN_LV_MAX + 1)])):
            idx.insert(i, region.boundary().bounds, obj=region)

        # Search for overlapping regions
        candidates = list(idx.intersection(point.bounds, objects=True))
        containing_regions = list[Region]
        for c in candidates:
            region = c.object
            if region.contains_point(point):
                containing_regions.append(region)
        return containing_regions


# Get administrative boundaries of level 2 (countries) around center with radius
def country_query(center, radius): 
    query = f"""
        [out:json];
        (
        relation["boundary"="administrative"]["admin_level"="2"](around:{radius * 1000},{center.latitude},{center.longitude});
        );
        out geom;
    """
    return query

def regions_query(country_name):
    query = f"""
        [out:json];
        area["name:en"="{country_name}"]["boundary"="administrative"]->.searchArea;
        relation["boundary"="administrative"][admin_level != 2](area.searchArea);
        out geom;
    """
    return query

def fetch_overpass_data(query):
    overpass_url = "http://overpass-api.de/api/interpreter"
    response = requests.get(overpass_url, params={'data': query})
    response.raise_for_status()
    return response.json()

def shape_obj_to_region(shape_obj: dict, compress=True) -> Region:
    lv = shape_obj['properties']['tags']['admin_level']
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

    original_point = None
    args = parser.parse_args()
    if args.random >= 1:
        original_point = geopy.location.Point(random.uniform(-90, 90), random.uniform(-180, 180))
    else:
        if args.latitude is None or args.longitude is None:
            raise SystemExit("Invalid arguments. Use option -h for help.")
        if args.latitude < -90.0 or args.latitude > 90.0:
            raise SystemExit("Latitude must be between -90 and 90.")
        if args.longitude < -180.0 or args.longitude > 180.0:
            raise SystemExit("Latitude must be between -180 and 180.")
        original_point = geopy.location.Point(args.latitude, args.longitude)

    # Generate a random point on a circle of radius R
    R = random.uniform(50, 150)  # Radius in km
    angle = random.uniform(0, 360)
    random_point = geopy.distance.geodesic(kilometers=R).destination(original_point, angle)

    # Create a second circle centered on the random point
    radius2 = R * random.uniform(2, 3)

    query = country_query(random_point, radius2)
    overpass_data = fetch_overpass_data(query)
    
    # Convert to shapely
    shape_objects = osm2geojson.json2shapes(overpass_data)
    countries = [shape_obj_to_country(obj) for obj in shape_objects]

    # Iterate over countries
    country = None
    point = shapely.geometry.Point(original_point.longitude, original_point.latitude)
    for c in countries:
        if c.contains_point(point):
            country = c
        else:
            print(f"{c.name} does not contain the point")

    if country is None:
        raise SystemError("The coordinates do not belong to any country's territory.")
    print(f"The point {original_point.latitude}, {original_point.longitude} is inside: {country.name}")

    # Download subregions data
    query = regions_query(country.name)
    overpass_data = fetch_overpass_data(query)
    shape_objects = osm2geojson.json2shapes(overpass_data)
    subregions = [shape_obj_to_region(obj) for obj in shape_objects]
    country.add_subregions(subregions)

    # Get the list of regions containing the point
    containing_regions = country.geolocate(point)

    print('List of containing regions:')
    for r in containing_regions:
        print(f'lv = {r.admin_level}, name = {r.name}')
    
    
