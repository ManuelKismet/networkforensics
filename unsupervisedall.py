# import logging
# import os
# from collections import Counter
# import numpy as np
# import pandas as pd
# from imblearn.over_sampling import SMOTE
# from imblearn.under_sampling import RandomUnderSampler
# from matplotlib import pyplot as plt
# from sklearn.decomposition import PCA
# from sklearn.metrics import (classification_report, make_scorer, f1_score, precision_score, recall_score, roc_auc_score,
#                              roc_curve)
# from sklearn.ensemble import IsolationForest
# from sklearn.model_selection import train_test_split, GridSearchCV
# from sklearn.preprocessing import StandardScaler, MinMaxScaler
# from sklearn.svm import OneClassSVM
# from main import myprint, file_path, read_parquet_dataset, data_balancing
# import seaborn as sns
#
# pd.set_option('display.width', None)
#
# # irrelevant_feature = ['Protocol', 'Flow Duration', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean',
# #                       'Fwd Pkt Len Std', 'Subflow Fwd Pkts',
# #                       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean',
# #                       'Flow IAT Std', 'Flow IAT Max', 'Subflow Fwd Byts',
# #                       'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean',
# #                       'Bwd IAT Std', 'Bwd IAT Max', 'Subflow Bwd Pkts',
# #                       'Bwd IAT Min', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
# #                       'FIN Flag Cnt', 'SYN Flag Cnt', 'Subflow Bwd Byts', 'Fwd Seg Size Min',
# #                       'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio',
# #                       'Init Fwd Win Byts', 'PSH Flag Cnt',
# #                       'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Init Bwd Win Byts',
# #                       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
# #                       'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
# #
# #
# # def data_preprocessing(data):
# #     dff = pd.concat(data, axis=0)
# #     df = dff.drop(irrelevant_feature, axis=1)
# #     print(df.sample(6))
# #     categories = ['Bot', 'FTP-BruteForce', 'SSH-Bruteforce', 'DDoS attacks-LOIC-HTTP', 'DDOS attack-LOIC-UDP',
# #                   'DDOS attack-HOIC', 'DoS attacks-Slowloris', 'DoS attacks-GoldenEye', 'DoS attacks-SlowHTTPTest',
# #                   'DoS attacks-Hulk', 'Infilteration', 'SQL Injection', 'Brute Force -XSS', 'Brute Force -Web']
# #
# #     cat = {'Benign': 0}
# #     cat.update({category: 1 for category in categories})
# #
# #     df['Label'] = pd.Series(df['Label']).map(cat)
# # Configure logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
#
#
# def remove_highly_correlated_features(df, threshold=0.7):
#     try:
#         # Calculate correlation matrix
#         corr_matrix = df.corr(method='pearson')
#         upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
#         to_drop = [column for column in upper.columns if any(upper[column].abs() > threshold)]
#
#         logging.info(f"Highly correlated features to drop (threshold={threshold}): {to_drop}")
#         df_reduced = df.drop(columns=to_drop)
#         return df_reduced, to_drop
#     except Exception as e:
#         logging.error(f"Error in removing highly correlated features: {e}")
#         raise
#
#
# def data_preprocessing(data):
#     try:
#         irrelevant_features = ['Protocol', 'Flow Duration', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean',
#                                'Fwd Pkt Len Std', 'Subflow Fwd Pkts', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
#                                'Bwd Pkt Len Mean',
#                                'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Subflow Fwd Byts',
#                                'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
#                                'Bwd IAT Mean',
#                                'Bwd IAT Std', 'Bwd IAT Max', 'Subflow Bwd Pkts', 'Bwd IAT Min', 'Pkt Len Min',
#                                'Pkt Len Max',
#                                'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
#                                'Subflow Bwd Byts',
#                                'Fwd Seg Size Min', 'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
#                                'ECE Flag Cnt',
#                                'Down/Up Ratio', 'Init Fwd Win Byts', 'PSH Flag Cnt', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg',
#                                'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Init Bwd Win Byts', 'Bwd Pkts/b Avg',
#                                'Bwd Blk Rate Avg',
#                                'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
#                                'Idle Max', 'Idle Min']
#         dff = pd.concat(data, axis=0)
#         df = dff.drop(columns=irrelevant_features)
#         logging.info("Irrelevant features dropped.")
#
#         categories = ['Bot', 'FTP-BruteForce', 'SSH-Bruteforce', 'DDoS attacks-LOIC-HTTP', 'DDOS attack-LOIC-UDP',
#                       'DDOS attack-HOIC', 'DoS attacks-Slowloris', 'DoS attacks-GoldenEye', 'DoS attacks-SlowHTTPTest',
#                       'DoS attacks-Hulk', 'Infilteration', 'SQL Injection', 'Brute Force -XSS', 'Brute Force -Web']
#
#         cat = {'Benign': 0}
#         cat.update({category: 1 for category in categories})
#         df['Label'] = df['Label'].map(cat)
#
#         # Remove highly correlated features
#         reduced_df, dropped_features = remove_highly_correlated_features(df.drop('Label', axis=1))
#         reduced_df['Label'] = df['Label']  # Re-add label after dropping correlated features
#         print(reduced_df.columns)
#         return reduced_df
#     except Exception as e:
#         logging.error(f"Error during data preprocessing: {e}")
#         raise
#
#     # val_count = df['Label'].value_counts()
#     # min_d_label = val_count.idxmin()
#     # min_lb_cnt = val_count[min_d_label]
#     #
#     # df.reset_index(drop=True, inplace=True)
#     # max_lb_index = df.index[df['Label'] != min_d_label]
#     # randIndex = np.random.choice(max_lb_index, min_lb_cnt, replace=False)
#     #
#     # maxSample = df.loc[randIndex]
#     # uSample = pd.concat([df[df['Label'] == min_d_label], maxSample], axis=0)
#     #
#     # y = uSample['Label']
#
#
# def balance_data(X, y):
#     try:
#         # smote = SMOTE()
#         # X_res, y_res = smote.fit_resample(X, y)
#         rus = RandomUnderSampler(random_state=42)
#         X_rus, y_rus = rus.fit_resample(X, y)
#         logging.info("Data balanced using SMOTE.")
#         return X_rus, y_rus
#     except Exception as e:
#         logging.error(f"Error during data balancing: {e}")
#         raise
#
#     # cor_met = uSample.corr(method='pearson')
#     # highly_correlated_pairs = []
#     #
#     # for i in range(len(cor_met.columns)):
#     #     for j in range(i + 1, len(cor_met.columns)):
#     #         if abs(cor_met.iloc[i, j]) > 0.7:
#     #             highly_correlated_pairs.append((cor_met.columns[i], cor_met.columns[j]))
#     # print(highly_correlated_pairs)
#     # correlated_items = [item for pair in highly_correlated_pairs for item in pair]
#     # item_counts = Counter(correlated_items)
#     # print(item_counts)
#     # cols_to_drop = [item for item, count in item_counts.items() if count > 5]
#     #
#     # x = uSample.drop(cols_to_drop + ['Label'], axis=1)
#     # print(x.sample(5))
#     # return x, y
#     # corr_matrix = Xd[0].corr(method='pearson')
#     # plt.figure(figsize=(10, 8))
#     # sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f")
#     # plt.title('Correlation Matrix')
#     # plt.show()
#
#
# # def scaling(data):
# #     scaler = StandardScaler()
# #     mscaler = MinMaxScaler()
# #     # mscaled = mscaler.fit_transform(data)
# #     scaled_d = scaler.fit_transform(data)
# #     return scaled_d
# def scaling(data):
#     try:
#         scaler = StandardScaler()
#         scaled_data = scaler.fit_transform(data)
#         logging.info("Data scaled.")
#         return scaled_data
#     except Exception as e:
#         logging.error(f"Error during data scaling: {e}")
#         raise
#
#
# # def tune_hyperparameters(X, y):
# #     try:
# #         param_grid = {
# #             'n_estimators': [50, 100, 200],
# #             'max_samples': ['auto', 0.5, 0.75],
# #             'contamination': ['auto', 0.1, 0.05],
# #             'bootstrap': [True, False],
# #         }
# #
# #         clf = IsolationForest(random_state=42)
# #         grid_search = GridSearchCV(clf, param_grid, cv=3, scoring='roc_auc', n_jobs=-1)
# #
# #         num_samples = int(0.05 * len(X))  # 10% of X
# #         indices = np.random.choice(np.arange(len(X)), size=num_samples, replace=False)
# #         X_sample = X[indices]
# #         y_sample = y[indices]
# #
# #         grid_search.fit(X_sample, y_sample)
# #         logging.info(f"Best hyperparameters found.{grid_search.best_estimator_}")
# #
# #         return grid_search.best_estimator_
# #
# #     except Exception as e:
# #         logging.error(f"Error during hyperparameter tuning: {e}")
# #         raise
#
#
# def plot_classification_report(report):
#     lines = report.split('\n')
#     classes = []
#     plotMat = []
#
#     for line in lines[2: (len(lines) - 3)]:
#         if line.strip():  # Check if the line is not empty
#             t = line.strip().split()
#             classes.append(t[0])
#             v = [float(x) for x in t[1: len(t) - 1]]
#             plotMat.append(v)
#
#     df_classification_report = pd.DataFrame(plotMat, columns=['precision', 'recall', 'f1-score'])
#     df_classification_report['class'] = classes
#
#     df_classification_report.set_index('class', inplace=True)
#
#     plt.figure(figsize=(8, 6))
#     sns.heatmap(df_classification_report, annot=True, cmap='coolwarm', fmt=".2f")
#     plt.title('Classification Report Heatmap')
#     plt.show()
#
#
# def plot_isolation_forest_pca(clf, trx, n_components=2):
#     pca = PCA(n_components=n_components)
#     X_pca = pca.fit_transform(trx)
#     xx, yy = np.meshgrid(np.linspace(-5, 5, 50), np.linspace(-5, 5, 50))
#
#     # Transform grid points to original feature space
#     xx_orig = pca.inverse_transform(np.c_[xx.ravel(), yy.ravel()])
#     Z = clf.decision_function(xx_orig)
#     Z = Z.reshape(xx.shape)
#
#     plt.figure(figsize=(10, 8))
#     plt.contourf(xx, yy, Z, cmap=plt.cm.coolwarm, levels=np.linspace(Z.min(), 0, 7), alpha=0.5)
#     plt.scatter(X_pca[:, 0], X_pca[:, 1], color='black')
#     plt.xlabel('Principal Component 1')
#     plt.ylabel('Principal Component 2')
#     plt.title('Isolation Forest Decision Boundaries (PCA)')
#     plt.show()
#
#
# def plot_roc_aoc(y, y_pred):
#     roc_auc = roc_auc_score(y, y_pred)
#     print("ROC-AUC Score:", roc_auc)
#
#     fpr, tpr, thresholds = roc_curve(y, y_pred)
#     plt.figure(figsize=(8, 6))
#     plt.plot(fpr, tpr, color='orange', lw=2, label='ROC Curve (area = %0.2f)' % roc_auc)
#     plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
#     plt.xlabel('False Positive Rate')
#     plt.ylabel('True Positive Rate')
#     plt.title('Receiver Operating Characteristic (ROC) Curve')
#     plt.legend(loc="lower right")
#     plt.show()
#
#
# # def predict(x, y):
# #     clf = IsolationForest(random_state=42, n_jobs=-1, n_estimators=100)
# #
# #     #[clf.fit(x) for k in range(3)]
# #     clf.fit(x)
# #     plot_isolation_forest_pca(clf, x)
# #     y_pred = clf.predict(x)
# #     y_pred[y_pred == 1] = 0  # Normal
# #     y_pred[y_pred == -1] = 1  # Anomaly
# #
# #     score = classification_report(y, y_pred)
# #     print(score)
# def predict(X, y):
#     try:
#         clf = IsolationForest(random_state=42, n_jobs=-1, n_estimators=50)
#         clf.fit(X)
#         y_pred = clf.predict(X)
#         y_pred = np.where(y_pred == 1, 0, 1)  # Convert predictions to binary labels
#         report = classification_report(y, y_pred)
#         logging.info("Prediction complete.")
#
#         plot_classification_report(report)
#         plot_isolation_forest_pca(clf, X)
#         plot_roc_aoc(y, y_pred)
#         return report, y_pred
#     except Exception as e:
#         logging.error(f"Error during prediction: {e}")
#         raise
#
#
# def main():
#     try:
#         paths = file_path()
#         p_data = read_parquet_dataset(paths)
#         preprocessed_data = data_preprocessing(p_data)
#         X, y = preprocessed_data.drop('Label', axis=1), preprocessed_data['Label']
#         X_balanced, y_balanced = balance_data(X, y)
#         X_scaled = scaling(X_balanced)
#         # best_clf = tune_hyperparameters(X_scaled, y_balanced)
#         report, _ = predict(X_scaled, y_balanced)
#         print(report)
#     except Exception as e:
#         logging.error(f"An error occurred in the main process: {e}")
#
#
# if __name__ == "__main__":
#     main()
#
# # if __name__ == '__main__':
# #     paths = file_path()
# #     p_data = read_parquet_dataset(paths)
# #     X_data, y_data = data_preprocessing(p_data)
# #     scaled = scaling(X_data)
# #     predict(scaled, y_data)
