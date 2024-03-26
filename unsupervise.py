import os
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.metrics import classification_report
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from main import myprint, file_path, read_parquet_dataset
import seaborn as sns


def data_preprocessing(data):
    X = data[0].drop(['Label'], axis=1)
    y = data[0]['Label']
    # corr_matrix = data[0].corr(method='pearson')
    # plt.figure(figsize=(10, 8))
    # sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f")
    # plt.title('Correlation Matrix')
    # plt.show()
    return X, y


def scaling(data):
    scaler = StandardScaler()
    # scaled_data = [scaler.fit_transform(entry.drop(['Label', 'Protocol'], axis=1)) for entry in data]
    scaled_data = scaler.fit_transform(data)
    return scaled_data


def model_train_test(xs_data, ydata):
    X_train, X_test, y_train, y_test = train_test_split(xs_data, ydata, test_size=0.2, random_state=42)
    y_train.replace('Benign', 0, inplace=True)
    y_train.replace('Bot', 1, inplace=True)
    clf = IsolationForest(contamination=0.2, random_state=42)
    y_pred = clf.fit_predict(X_train)
    y_pred[y_pred == 1] = 0  # Normal
    y_pred[y_pred == -1] = 1  # Anomaly
    print(classification_report(y_train, y_pred))


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)
    X_data, y_data = data_preprocessing(p_data)
    scaled = scaling(X_data)
    model_train_test(scaled, y_data)

    # Assuming label information is not available in this case
    # labels = np.zeros(len(scaled_data))  # Dummy labels (all normal)

    # Splitting data into train and test sets (for unsupervised learning, we don't use labels)
    # X_train, X_test = train_test_split(scaled_data, test_size=0.3, random_state=42)

    # model_train_test(X_test, labels)
