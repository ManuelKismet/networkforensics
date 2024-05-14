import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler


# DATA_DIR = os.environ['DataSetPath']  # r'C:\Users\jd Phones\Documents\Thesis\dataSet'

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
    print('read files')
    return path


def read_parquet_dataset(path):
    dataset = [pd.read_parquet(item) for item in path]
    dataset = pd.concat(dataset, axis=0)
    print('concate data')
    return dataset


def binary_labeling(data):
    label_map = {'Benign': 0}
    attack_labels = ['Bot', 'Brute Force -Web', 'Brute Force -XSS', 'SQL Injection',
                     'Infilteration', 'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest',
                     'DoS attacks-GoldenEye', 'DoS attacks-Slowloris', 'DDOS attack-HOIC',
                     'DDOS attack-LOIC-UDP', 'DDoS attacks-LOIC-HTTP', 'FTP-BruteForce',
                     'SSH-Bruteforce']
    label_map.update({label: 1 for label in attack_labels})

    data['Label'] = data['Label'].map(label_map)
    print('labeling done')
    return data


def data_balancing(data):
    d_count = data['Label'].value_counts()
    min_d_label = d_count.idxmin()  # 1 as index of the min val count
    min_d_count = d_count[min_d_label]  # 541
    max_d_ind = data.index[data['Label'] != min_d_label]
    rand_ind = np.random.choice(max_d_ind, min_d_count, replace=False)
    max_d_samp = data.loc[rand_ind]
    u_sampled = pd.concat([data[data['Label'] == min_d_label], max_d_samp], axis=0)
    data = u_sampled
    print('balancing done')
    return data


def train_test_data(usd):  # usd: under sampled data
    train, test = train_test_split(usd, test_size=0.3, random_state=42)
    training = train
    testing = test
    print('train test split done')
    return training, testing


def xy_split(tr_data, te_data):  # training and testing data
    x_train = tr_data.drop(['Label', 'Protocol'], axis=1)
    x_test = te_data.drop(['Label', 'Protocol'], axis=1)
    y_train = tr_data['Label']
    y_test = te_data['Label']
    print('x and y assinged')
    return x_train, x_test, y_train, y_test


def scaling(xtr_data, xte_data):  # training data
    scaler = StandardScaler()
    scaled_tr_data = scaler.fit_transform(xtr_data)
    scaled_te_data = scaler.fit_transform(xte_data)
    print('scaling done')
    return scaled_tr_data, scaled_te_data


def model_train_test(xt_data, yt_data, xte_data, yte_data):  # training data and test data
    params = {'max_depth': [5, 10], 'min_samples_split': [2, 5],
              'min_samples_leaf': [1, 2], 'criterion': ['gini', 'entropy'], 'random_state': [42, 0],
              'n_estimators': [50, 100]}
    dtc = DecisionTreeClassifier(criterion='entropy', max_depth=10, min_samples_leaf=1,
                                 min_samples_split=5)  # dtc: decision tree classifier

    dtc.fit(xt_data, yt_data)
    y_pred = dtc.predict(xte_data)
    print(classification_report(yte_data, y_pred))

    # hyper param tuning
    # rd = RandomizedSearchCV(rdf, param_distributions=params, n_iter=10, cv=3, n_jobs=-1)
    # rd.fit(xt_data, yt_data)
    # print(rd.best_params_)
    # print(rd.best_score_)


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)  # p: parquet data
    b_data = binary_labeling(p_data)
    u_samp_data = data_balancing(b_data)  # under sampled data
    train_d, test_d = train_test_data(u_samp_data)
    xtr, xte, ytr, yte = xy_split(train_d, test_d)  # xtrain xtest ytrain ytest
    sctr, scte = scaling(xtr, xte)  # scaled train and test data
    model_train_test(sctr, ytr, scte, yte)
