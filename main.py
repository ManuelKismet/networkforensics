import os

import numpy as np
import pandas as pd


def pp(*args):
    for i in range(0, len(args), 2):
        arg = args[i]
        comment = args[i + 1] if i + 1 < len(args) else None
        if comment:
            print(f"Argument {i // 2 + 1}: {arg}: {comment}")
        else:
            print(f"Argument {i // 2 + 1}: {arg}")


def file_path():
    path = []
    for root, dirs, files in os.walk(r'C:\Users\jd Phones\Documents\Thesis\dataSet'):
        # print(root, '\n', dirs, '\n', files)
        for file in files:
            if file.endswith('parquet'):
                pfp = os.path.join(root, file)  # pfp: parquet file path
                path.append(pfp)
    # [print(item) for item in path]
    return path


def read_parquet_dataset(path):
    dataset = [pd.read_parquet(item) for item in path]
    return dataset


def binary_labeling(data):
    benign = 0
    bot = 1
    catt = []
    labels = ['Bot', 'Brute Force -Web', 'Brute Force -XSS',
              'SQL Injection', 'Infilteration', 'DoS attacks-Hulk',
              'DoS attacks-SlowHTTPTest', 'DoS attacks-GoldenEye',
              'DoS attacks-Slowloris', 'DDOS attack-HOIC', 'DDOS attack-LOIC-UDP',
              'DDoS attacks-LOIC-HTTP', 'FTP-BruteForce', 'SSH-Bruteforce']
    for i, d in enumerate(data):
        # print(f'~~~~~~~~~~~~~~~~~~~~~\n{data[i]["Label"].value_counts()}')
        catt.append(data[i]["Label"].cat.categories)
        if 'Benign' in catt[i].values:
            d['Label'] = d['Label'].replace('Benign', benign)
        for val in labels:
            if val in catt[i].values:
                d['Label'] = d['Label'].replace(val, bot)
        # print(f'~~~~~~~~~~~~~~~~~~~~~\n{data[i]["Label"].value_counts()}')
    return data


def data_balancing(data):
    for i in range(len(data)):
        pp(data[9]['Label'].value_counts(), 'last data set')
        # d_count = data[0]['Label'].value_counts()
        # min_d_label = d_count.idxmin()
        # min_d_count = d_count[min_d_label]
        # print(f"label{data[0]['Label']}", '\n', f'min label{min_d_label}')
        # max_d_ind = data[0][data[0]['Label'] != min_d_label].index
        # rand_ind = np.random.choice(max_d_ind, min_d_count, replace=False)
        # max_d_samp = data[i].loc[rand_ind]
        # u_sampled = pd.concat([data[i][data[i]['Label'] == min_d_label], max_d_samp], axis=1)
        # u_sampled.dropna(inplace=True)
        # print(f'max index{max_d_ind}')


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)  # p: parquet data
    b_data = binary_labeling(p_data)
    data_balancing(b_data)
