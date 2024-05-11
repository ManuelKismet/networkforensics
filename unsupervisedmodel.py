import os
from collections import Counter
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.decomposition import PCA
from sklearn.metrics import classification_report, make_scorer, f1_score, precision_score, recall_score, roc_auc_score, \
    roc_curve
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.svm import OneClassSVM
from main import myprint, file_path, read_parquet_dataset, data_balancing
import seaborn as sns

pd.set_option('display.width', None)

feature = ['Protocol', 'Flow Duration', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Subflow Fwd Pkts',
           'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Subflow Fwd Byts',
           'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Subflow Bwd Pkts',
           'Bwd IAT Min', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'Subflow Bwd Byts', 'Fwd Seg Size Min',
           'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Init Fwd Win Byts', 'PSH Flag Cnt',
           'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Init Bwd Win Byts',
           'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']


def data_preprocessing(data):
    dff = pd.concat(data, axis=0)
    df = dff.drop(feature, axis=1)
    print(df.sample(6))
    categories = ['Bot', 'FTP-BruteForce', 'SSH-Bruteforce', 'DDoS attacks-LOIC-HTTP', 'DDOS attack-LOIC-UDP',
                  'DDOS attack-HOIC', 'DoS attacks-Slowloris', 'DoS attacks-GoldenEye', 'DoS attacks-SlowHTTPTest',
                  'DoS attacks-Hulk', 'Infilteration', 'SQL Injection', 'Brute Force -XSS', 'Brute Force -Web']

    cat = {'Benign': 0}
    cat.update({category: 1 for category in categories})

    df['Label'] = pd.Series(df['Label']).map(cat)

    val_count = df['Label'].value_counts()
    min_d_label = val_count.idxmin()
    min_lb_cnt = val_count[min_d_label]

    df.reset_index(drop=True, inplace=True)
    max_lb_index = df.index[df['Label'] != min_d_label]
    randIndex = np.random.choice(max_lb_index, min_lb_cnt, replace=False)

    maxSample = df.loc[randIndex]
    uSample = pd.concat([df[df['Label'] == min_d_label], maxSample], axis=0)

    y = uSample['Label']

    cor_met = uSample.corr(method='pearson')
    highly_correlated_pairs = []

    for i in range(len(cor_met.columns)):
        for j in range(i + 1, len(cor_met.columns)):
            if abs(cor_met.iloc[i, j]) > 0.7:
                highly_correlated_pairs.append((cor_met.columns[i], cor_met.columns[j]))
    print(highly_correlated_pairs)
    correlated_items = [item for pair in highly_correlated_pairs for item in pair]
    item_counts = Counter(correlated_items)
    print(item_counts)
    cols_to_drop = [item for item, count in item_counts.items() if count > 5]

    x = uSample.drop(cols_to_drop + ['Label'], axis=1)
    print(x.sample(5))
    return x, y
    # corr_matrix = Xd[0].corr(method='pearson')
    # plt.figure(figsize=(10, 8))
    # sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f")
    # plt.title('Correlation Matrix')
    # plt.show()


def scaling(data):
    scaler = StandardScaler()
    mscaler = MinMaxScaler()
    # mscaled = mscaler.fit_transform(data)
    scaled_d = scaler.fit_transform(data)
    return scaled_d


def plot_classification_report(report):
    lines = report.split('\n')
    classes = []
    plotMat = []

    for line in lines[2: (len(lines) - 3)]:
        if line.strip():  # Check if the line is not empty
            t = line.strip().split()
            classes.append(t[0])
            v = [float(x) for x in t[1: len(t) - 1]]
            plotMat.append(v)

    df_classification_report = pd.DataFrame(plotMat, columns=['precision', 'recall', 'f1-score'])
    df_classification_report['class'] = classes

    df_classification_report.set_index('class', inplace=True)

    plt.figure(figsize=(8, 6))
    sns.heatmap(df_classification_report, annot=True, cmap='coolwarm', fmt=".2f")
    plt.title('Classification Report Heatmap')
    plt.show()


def plot_isolation_forest_pca(clf, trx, n_components=2):
    pca = PCA(n_components=n_components)
    X_pca = pca.fit_transform(trx)
    xx, yy = np.meshgrid(np.linspace(-5, 5, 50), np.linspace(-5, 5, 50))

    # Transform grid points to original feature space
    xx_orig = pca.inverse_transform(np.c_[xx.ravel(), yy.ravel()])
    Z = clf.decision_function(xx_orig)
    Z = Z.reshape(xx.shape)

    plt.figure(figsize=(10, 8))
    plt.contourf(xx, yy, Z, cmap=plt.cm.coolwarm, levels=np.linspace(Z.min(), 0, 7), alpha=0.5)
    plt.scatter(X_pca[:, 0], X_pca[:, 1], color='black')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.title('Isolation Forest Decision Boundaries (PCA)')
    plt.show()


def predict(x, y):
    clf = IsolationForest(random_state=42, n_jobs=-1, n_estimators=50)

    #[clf.fit(x) for k in range(3)]
    clf.fit(x)
    plot_isolation_forest_pca(clf, x)
    y_pred = clf.predict(x)
    y_pred[y_pred == 1] = 0  # Normal
    y_pred[y_pred == -1] = 1  # Anomaly

    score = classification_report(y, y_pred)
    print(score)

    plot_classification_report(score)
    roc_auc = roc_auc_score(y, y_pred)
    print("ROC-AUC Score:", roc_auc)

    fpr, tpr, thresholds = roc_curve(y, y_pred)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='orange', lw=2, label='ROC Curve (area = %0.2f)' % roc_auc)
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.show()


if __name__ == '__main__':
    paths = file_path()
    p_data = read_parquet_dataset(paths)
    X_data, y_data = data_preprocessing(p_data)
    scaled = scaling(X_data)
    predict(scaled, y_data)