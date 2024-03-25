import os
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from main import myprint, file_path, read_parquet_dataset


def data_preprocessing(data):
    print(data[0].info())
    return data


def scaling(data):
    scaler = StandardScaler()
    scaled_data = [scaler.fit_transform(entry.drop(['Label', 'Protocol'], axis=1)) for entry in data]
    return scaled_data


def model_train_test(x_data, y_data):
    clf = IsolationForest(contamination=0.1, random_state=42)
    y_pred = clf.fit_predict(x_data)
    y_pred[y_pred == 1] = 0  # Normal
    y_pred[y_pred == -1] = 1  # Anomaly
    print(classification_report(y_data, y_pred))


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)
    preprocessed_data = data_preprocessing(p_data)

    # Assuming label information is not available in this case
    # labels = np.zeros(len(scaled_data))  # Dummy labels (all normal)

    # Splitting data into train and test sets (for unsupervised learning, we don't use labels)
    # X_train, X_test = train_test_split(scaled_data, test_size=0.3, random_state=42)

    # model_train_test(X_test, labels)
