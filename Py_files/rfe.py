import time
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFECV
from sklearn.model_selection import train_test_split, StratifiedKFold

start_time = time.time()
print("\n\nStarting rfe script")

df = pd.read_csv('dataset_with_label.csv')
df.drop('Unnamed: 0', axis=1, inplace=True)

# PRINT DATASET FEATURES NAMES ____________________
nb_features = 0
for col in df.columns:
    nb_features += 1
    # print(col)
print('Nb of features:', nb_features)

X = df.iloc[:, 0:-1]
Y = df['label']  # Labels

# PERFORM RECURSIVE FEATURES ELIMINATION _____________________
print('\nStart performing rfecv')

min_features_to_select = 1  # Minimum number of features to consider
rfecv = RFECV(
    estimator=RandomForestClassifier(n_estimators=100),
    step=1,
    cv=StratifiedKFold(2),
    scoring="accuracy",
    min_features_to_select=min_features_to_select)
rfecv.fit(X, Y)

X_rfe = rfecv.transform(X)
print("Num Features Before:", X.shape[1])
print("Num Features After:", X_rfe.shape[1])

features_kept = pd.DataFrame({'columns': X.columns, 'Kept': rfecv.support_})
print('Features kept :\n', features_kept)

X_new_df = X.iloc[:, rfecv.support_]
X_new_df.to_csv('dataset.csv')

print('\nRunning dataset script took {} seconds'.format(time.time() - start_time))
