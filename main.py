import os
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def myprint(*args):
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
        d_count = data[i]['Label'].value_counts()
        min_d_label = d_count.idxmin()  # 1 as index of the min val count
        min_d_count = d_count[min_d_label]  # 541
        max_d_ind = data[i][data[i]['Label'] != min_d_label].index
        rand_ind = np.random.choice(max_d_ind, min_d_count, replace=False)
        max_d_samp = data[i].loc[rand_ind]
        u_sampled = pd.concat([data[i][data[i]['Label'] == min_d_label], max_d_samp], axis=0)
        data[i] = u_sampled
    return data


def train_test_data(usd):  # usd: under sampled data
    training = []
    testing = []
    for entry in usd:
        train, test = train_test_split(entry, test_size=0.3, random_state=42)
        training.append(train)
        testing.append(test)
    return training, testing


def xy_split(tr_data, te_data):  # training and testing data
    x_train, x_test, y_train, y_test = [], [], [], []
    for tr, te in zip(tr_data, te_data):
        x_train.append(tr.drop(['Label', 'Protocol'], axis=1))
        x_test.append(te.drop(['Label', 'Protocol'], axis=1))
        y_train.append(tr['Label'])
        y_test.append(te['Label'])
    myprint(x_train[1].shape, 'x train', x_test[1].shape, 'x test',
            y_train[1].shape, 'y train', y_test[1].shape, 'y test')
    return x_train, x_test, y_train, y_test


def scaling(xtr_data, xte_data):  # training data
    scaled_tr_data = []
    scaled_te_data = []
    scaler = StandardScaler()
    for entr1, entr2 in zip(xtr_data, xte_data):
        scaled_tr_data.append(scaler.fit_transform(entr1))
        scaled_tr_data.append(scaler.fit_transform(entr2))
    myprint(scaled_tr_data[1].shape, 'scaled train', scaled_tr_data[1].shape, 'scaled test')
    return scaled_tr_data, scaled_te_data


def model_train_test(xt_data, yt_data, xte_data, yte_data):  # training data and test data
    myprint(xt_data[1].shape, 'xtrain', xte_data[1].shape, 'xtest',
            yt_data[1].shape, 'ytrain', yte_data[1].shape, 'ytest')
    dtc = DecisionTreeClassifier()  # dtc: decision tree classifier
    dtc.fit(xt_data[1], yt_data[1])
    y_pred = dtc.predict(xte_data[1])
    print(classification_report(yte_data[1], y_pred))


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)  # p: parquet data
    b_data = binary_labeling(p_data)
    u_samp_data = data_balancing(b_data)  # under sampled data
    train_d, test_d = train_test_data(u_samp_data)
    xtr, xte, ytr, yte = xy_split(train_d, test_d)  # xtrain xtest ytrain ytest
    sctr, scte = scaling(xtr, xte)  # scaled train and test data
    model_train_test(sctr, ytr, scte, yte)
