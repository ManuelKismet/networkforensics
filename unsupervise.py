import os
from collections import Counter

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.metrics import classification_report, make_scorer, f1_score, precision_score, recall_score
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from main import myprint, file_path, read_parquet_dataset, data_balancing
import seaborn as sns


def data_preprocessing(data):
    corXd = []
    yd = []  # ydata

    categories = ['Bot', 'FTP-BruteForce', 'SSH-Bruteforce', 'DDoS attacks-LOIC-HTTP', 'DDOS attack-LOIC-UDP',
                  'DDOS attack-HOIC', 'DoS attacks-Slowloris', 'DoS attacks-GoldenEye', 'DoS attacks-SlowHTTPTest',
                  'DoS attacks-Hulk', 'Infilteration', 'SQL Injection', 'Brute Force -XSS', 'Brute Force -Web']

    cat = {'Benign': 0}
    cat.update({category: 1 for category in categories})

    for entry in data:
        entry['Label'] = pd.Series(entry['Label']).map(cat)

        val_count = entry['Label'].value_counts()
        min_d_label = val_count.idxmin()
        min_d_cnt = val_count[min_d_label]

        max_d_index = entry.index[entry['Label'] != min_d_label]
        randIndex = np.random.choice(max_d_index, min_d_cnt, replace=False)

        maxSample = entry.loc[randIndex]

        uSample = pd.concat([entry[entry['Label'] == min_d_label], maxSample], axis=0)
        uSample.reset_index(drop=True, inplace=True)

        yd.append(uSample['Label'])

        cor_met = uSample.corr(method='pearson')
        highly_correlated_pairs = []

        for i in range(len(cor_met.columns)):
            for j in range(i + 1, len(cor_met.columns)):
                if abs(cor_met.iloc[i, j]) > 0.8:  # Adjust threshold as needed
                    highly_correlated_pairs.append((cor_met.columns[i], cor_met.columns[j]))

        correlated_items = [item for pair in highly_correlated_pairs for item in pair]
        item_counts = Counter(correlated_items)

        cols_to_drop = [item for item, count in item_counts.items() if count > 5]

        corXd.append(uSample.drop(cols_to_drop, axis=1))

    return corXd, yd
    # corr_matrix = Xd[0].corr(method='pearson')
    # plt.figure(figsize=(10, 8))
    # sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f")
    # plt.title('Correlation Matrix')
    # plt.show()


def scaling(data):
    scaler = StandardScaler()
    scaled_data = []
    # scaled_data = [scaler.fit_transform(entry.drop(['Label', 'Protocol'], axis=1)) for entry in data]
    for i in range(len(data)):
        scaled_data.append(scaler.fit_transform(data[i]))
    return scaled_data


# def model_train_test(xs_data, ydata):  # x scaled data
#     print(dir(np.ndarray))
#     for i in range(len(xs_data)):
#         # X_train, X_test, y_train, y_test = train_test_split(xs_data, ydata, test_size=0.2, random_state=42)
#         xs_data[i].replace('Benign', 0, inplace=True)
#         ydata[i].replace('Bot', 1, inplace=True)
#     return xs_data, ydata


def predict(x, y):
    clf = IsolationForest(random_state=42)
    param_grid = {
        'n_estimators': [50, 100, 150],
        'max_samples': [0.5, 0.7, 0.9],
        'contamination': [0.01, 0.05, 0.1, 0.2]
    }
    scorer = make_scorer(f1_score, average='micro')  # e.g., f1_score, precision, recall)
    grid_search = GridSearchCV(estimator=clf, param_grid=param_grid, scoring=scorer, cv=5)
    # for i in range(len(x)):
    grid_search.fit(x[0], None)
    best_params = grid_search.best_params_
    best_model = IsolationForest(**best_params, random_state=42)
    best_model.fit(x[0])
    y_pred = best_model.predict(x[0])
    y_pred[y_pred == 1] = 0  # Normal
    y_pred[y_pred == -1] = 1  # Anomaly
    f1 = f1_score(y[0], y_pred)

    print("F1 Score:", f1)
        # print(classification_report(y[i], y_pred))


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)
    # balance_data = data_balancing(p_data)
    X_data, y_data = data_preprocessing(p_data)
    scaled = scaling(X_data)
    #    xx, yy = model_train_test(scaled, y_data)
    predict(scaled, y_data)

    # Assuming label information is not available in this case
    # labels = np.zeros(len(scaled_data))  # Dummy labels (all normal)

    # Splitting data into train and test sets (for unsupervised learning, we don't use labels)
    # X_train, X_test = train_test_split(scaled_data, test_size=0.3, random_state=42)

    # model_train_test(X_test, labels)
