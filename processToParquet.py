import numpy as np
import pandas as pd
import os
from fastai.tabular.all import df_shrink
from fastcore.parallel import *


def read_file_path():  # data processing
    """
    :rtype: object
    reads csv file path
    """
    path = []
    for root, dirs, files in os.walk(r'C:\Users\jd Phones\Documents\Thesis\dataSet'):
        # print(root, '\n', dirs, '\n', files)
        for file in files:
            if file.endswith('csv'):
                csv_fp = os.path.join(root, file)  # csv file path
                path.append(csv_fp)
    # [print(item) for item in path]
    return path


def read_data_set(paths: list):
    dsl = [pd.read_csv(fp) for fp in paths]  # dsl: data set list
    print(dsl[0].dtypes)
    sdsl = parallel(f=df_shrink, items=dsl)
    # sdsl = []  # shrinked data set list
    # for dsi in dsl:  # dsi: data set item
    #     sdsi = df_shrink(dsi)  # sdsi: shrinked data set item
    #     sdsl.append(sdsi)
    print(sdsl[0].dtypes)
    return sdsl


def clean_dataset(sdsl):
    dc = ["Flow ID",
          'Fwd Header Length.1',
          "Source IP", "Src IP",
          "Source Port", "Src Port",
          "Destination IP", "Dst IP",
          "Destination Port", "Dst Port",
          "Timestamp", ]  # dc: data columns
    [print(le.shape) for le in sdsl]  # le:list entry
    for li in sdsl:  # li: list item in dsl
        li.columns = li.columns.str.strip()
        li.drop(columns=dc, inplace=True, errors='ignore')
        li.replace([np.inf, -np.inf], np.nan,  inplace=True)
        li.dropna(inplace=True)
        li.drop_duplicates(inplace=True)
        li.reset_index(inplace=True, drop=True)
    [print(le.shape) for le in sdsl]
    return sdsl


def write_to_parquet(data, path):
    for i, df in enumerate(data):
        df.to_parquet(path[i].split("/")[-1].replace(".csv", ".parquet"))


if __name__ == '__main__':
    path_list = read_file_path()
    dataset = read_data_set(path_list)
    cds = clean_dataset(dataset)  # cds: cleaned data set
    write_to_parquet(cds, path_list)
