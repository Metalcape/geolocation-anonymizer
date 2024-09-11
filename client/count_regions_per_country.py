import shapely
import osm2geojson
import argparse
import pandas as pd
import numpy as np
import os

import overpass_downloader as od

NAMES_PATH = './country_names.csv'
RESULT_PATH = './region_stats.csv'

def get_regions_count(r: pd.Series) -> pd.Series:
    if pd.isna(r['name_en']):
        name = r['name']
    else:
        name = r['name_en']
    
    country = od.Country(name)
    # Try to load country data from cache
    try:
        country = od.Country.deserialize(name)
    except FileNotFoundError:
        # Download subregions data
        query = od.regions_query(name)
        overpass_data = od.fetch_overpass_data(query)
        shape_objects = osm2geojson.json2shapes(overpass_data)
        subregions = [od.shape_obj_to_region(obj) for obj in shape_objects]
        country.add_subregions(subregions)
        # Save to cache
        country.serialize() 
    
    for k in country.subregions.keys():
        count = len(country.subregions[k])
        lv = str.split(k, '_')[1]
        r[f'LV{lv}_regions'] = count
    
    return r
    
if __name__ == "__main__":
    
    if not os.path.exists(RESULT_PATH):
        if not os.path.exists(NAMES_PATH):
            overpass_data = od.fetch_overpass_data(od.COUNTRIES_QUERY)
            shape_objects = osm2geojson.json2shapes(overpass_data)
            country_names = {'name': [], 'name_en': []}
            for obj in shape_objects:
                try:
                    name_en = obj['properties']['tags']['name']
                    country_names['name'].append(name_en)
                except KeyError:
                    country_names['name'].append(None)      
                try:
                    name_en = obj['properties']['tags']['name:en']
                    country_names['name_en'].append(name_en)
                except KeyError:
                    country_names['name_en'].append(None)
            df = pd.DataFrame(data=country_names)
            df.to_csv(NAMES_PATH)
        else:
            df = pd.read_csv(NAMES_PATH)
    
        for i in range(3, 12):
            df[f'LV{i}_regions'] = 0
        
        df.query('name.notna() | name_en.notna()', inplace=True)
        df = df.apply(get_regions_count, axis=1)
        df.reset_index(inplace=True, drop=True)
        df.drop(df.columns[df.columns.str.contains('unnamed', case=False)], axis=1, inplace=True)
        df.to_csv(RESULT_PATH)
    else:
        df = pd.read_csv(RESULT_PATH)

    print(df)
