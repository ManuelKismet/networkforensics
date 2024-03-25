import os
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler


# DATA_DIR = os.environ['DataSetPath']  # r'C:\Users\jd Phones\Documents\Thesis\dataSet'
index = 0


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
    myprint(usd[index].shape, 'full data set')
    training = []
    testing = []
    for entry in usd:
        train, test = train_test_split(entry, test_size=0.3, random_state=42)
        training.append(train)
        testing.append(test)
    myprint(training[index].shape, '70 percent training set',
            testing[index].shape, '70 percent testing set')
    return training, testing


def xy_split(tr_data, te_data):  # training and testing data
    x_train, x_test, y_train, y_test = [], [], [], []
    for tr, te in zip(tr_data, te_data):
        x_train.append(tr.drop(['Label', 'Protocol'], axis=1))
        x_test.append(te.drop(['Label', 'Protocol'], axis=1))
        y_train.append(tr['Label'])
        y_test.append(te['Label'])
    myprint(x_train[index].shape, 'x train', x_test[index].shape, 'x test',
            y_train[index].shape, 'y train', y_test[index].shape, 'y test')
    return x_train, x_test, y_train, y_test


def scaling(xtr_data, xte_data):  # training data
    scaled_tr_data = []
    scaled_te_data = []
    scaler = StandardScaler()
    for entr1, entr2 in zip(xtr_data, xte_data):
        scaled_tr_data.append(scaler.fit_transform(entr1))
        scaled_te_data.append(scaler.fit_transform(entr2))
    myprint(scaled_tr_data[index].shape, 'scaled train', scaled_te_data[index].shape, 'scaled test')
    return scaled_tr_data, scaled_te_data


def model_train_test(xt_data, yt_data, xte_data, yte_data):  # training data and test data
    myprint(xt_data[index].shape, 'xtrain', xte_data[index].shape, 'xtest',
            yt_data[index].shape, 'ytrain', yte_data[index].shape, 'ytest')
    params = {'max_depth': [2, 4, 7, 10], 'min_samples_split': [2, 3, 5],
              'min_samples_leaf': [1, 2, 3, 5], 'criterion': ['gini', 'entropy']}
    dtc = DecisionTreeClassifier(criterion='entropy', max_depth=5)  # dtc: decision tree classifier
    # dtc.fit(xt_data[index], yt_data[index])
    # y_pred = dtc.predict(xte_data[index])
    # print(classification_report(yte_data[index], y_pred))

# hyper param tuning
    rd = RandomizedSearchCV(dtc, param_distributions=params, n_iter=10, cv=3, n_jobs=-1)
    rd.fit(xt_data[index], yt_data[index])
    print(rd.best_params_)
    print(rd.best_score_)


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)  # p: parquet data
    b_data = binary_labeling(p_data)
    u_samp_data = data_balancing(b_data)  # under sampled data
    train_d, test_d = train_test_data(u_samp_data)
    xtr, xte, ytr, yte = xy_split(train_d, test_d)  # xtrain xtest ytrain ytest
    sctr, scte = scaling(xtr, xte)  # scaled train and test data
    model_train_test(sctr, ytr, scte, yte)

# import os
# import numpy as np
# import pandas as pd
# from sklearn.metrics import classification_report
# from sklearn.ensemble import IsolationForest
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler
#
#
# def myprint(*args):
#     for i in range(0, len(args), 2):
#         arg = args[i]
#         comment = args[i + 1] if i + 1 < len(args) else None
#         if comment:
#             print(f"Argument {i // 2 + 1}: {arg}: {comment}")
#         else:
#             print(f"Argument {i // 2 + 1}: {arg}")
#
#
# def file_path():
#     path = []
#     for root, dirs, files in os.walk(r'C:\Users\jd Phones\Documents\Thesis\dataSet'):
#         for file in files:
#             if file.endswith('parquet'):
#                 pfp = os.path.join(root, file)  # pfp: parquet file path
#                 path.append(pfp)
#     return path
#
#
# def read_parquet_dataset(path):
#     dataset = [pd.read_parquet(item) for item in path]
#     return dataset
#
#
# def data_preprocessing(data):
#     # Perform any necessary preprocessing steps here
#     return data
#
#
# def scaling(data):
#     scaler = StandardScaler()
#     scaled_data = [scaler.fit_transform(entry.drop(['Label', 'Protocol'], axis=1)) for entry in data]
#     return scaled_data
#
#
# def model_train_test(x_data, y_data):
#     clf = IsolationForest(contamination=0.1, random_state=42)
#     y_pred = clf.fit_predict(x_data)
#     y_pred[y_pred == 1] = 0  # Normal
#     y_pred[y_pred == -1] = 1  # Anomaly
#     print(classification_report(y_data, y_pred))
#
#
# if __name__ == '__main__':
#     paths = file_path()
#     p_data = read_parquet_dataset(paths)
#     preprocessed_data = data_preprocessing(p_data)
#     scaled_data = scaling(preprocessed_data)
#
#     # Assuming label information is not available in this case
#     labels = np.zeros(len(scaled_data))  # Dummy labels (all normal)
#
#     # Splitting data into train and test sets (for unsupervised learning, we don't use labels)
#     X_train, X_test = train_test_split(scaled_data, test_size=0.3, random_state=42)
#
#     model_train_test(X_test, labels)
