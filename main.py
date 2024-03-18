import os
import pandas as pd


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


def processing(data):
    benign = 0
    bot = 1
    catt = []
    labels = ['Bot', 'Brute Force -Web', 'Brute Force -XSS',
              'SQL Injection', 'Infilteration', 'DoS attacks-Hulk' 
              'DoS attacks-SlowHTTPTest', 'DoS attacks-GoldenEye',
              'DoS attacks-Slowloris', 'DDOS attack-HOIC', 'DDOS attack-LOIC-UDP',
              'DDoS attacks-LOIC-HTTP', 'FTP-BruteForce', 'SSH-Bruteforce']
    for i, d in enumerate(data):
        print(f'~~~~~~~~~~~~~~~~~~~~~\n{data[i]["Label"].value_counts()}')
        catt.append(data[i]["Label"].cat.categories)
        if 'Benign' in catt[i].values:
            d['Label'] = d['Label'].replace('Benign', benign)
        for val in labels:
            if val in catt[i].values:
                d['Label'] = d['Label'].replace(val, bot)
        print(f'~~~~~~~~~~~~~~~~~~~~~\n{data[i]["Label"].value_counts()}')


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)  # p: parquet data
    processing(p_data)
