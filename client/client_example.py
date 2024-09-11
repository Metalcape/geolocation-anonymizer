import shapely
import random
import osm2geojson
import argparse

import overpass_downloader as od

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

    country = od.find_country(point)
    if country is None:
        raise SystemError("The coordinates do not belong to any country's territory.")
    print(f"The point {point.y}, {point.x} is inside: {country.name}")

    # Try to load country data from cache
    try:
        country = od.Country.deserialize(country.name)
    except FileNotFoundError:
        # Download subregions data
        query = od.regions_query(country.name)
        overpass_data = od.fetch_overpass_data(query)
        shape_objects = osm2geojson.json2shapes(overpass_data)
        subregions = [od.shape_obj_to_region(obj) for obj in shape_objects]
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
    
    # TODO: Encrypt vector with BFV, exchange public key with server, send vector to server, await response
    