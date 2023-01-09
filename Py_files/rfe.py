import random
import time

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFECV
from sklearn.model_selection import train_test_split, StratifiedKFold

start_time = time.time()
print("\n\nStarting AI script")

df =pd.read_csv('dataset_with_label.csv')

# REMOVE SOME FEATURES ___________________________
df.drop('Unnamed: 0.2', axis=1, inplace=True)
df.drop('Unnamed: 0.1', axis=1, inplace=True)
df.drop('Unnamed: 0', axis=1, inplace=True)
df.drop('t_start', axis=1, inplace=True)
df.drop('t_end', axis=1, inplace=True)
df.drop('ip_src', axis=1, inplace=True)
df.drop('ip_dst', axis=1, inplace=True)
df.drop('sec_1_ip_src', axis=1, inplace=True)
df.drop('sec_2_ip_src', axis=1, inplace=True)
df.drop('sec_3_ip_src', axis=1, inplace=True)
df.drop('sec_4_ip_src', axis=1, inplace=True)
df.drop('sec_5_ip_src', axis=1, inplace=True)
print('Dataframe before removing benign traffic\n', df)


# REMOVE INSTANCIES OF BENIGN TRAFFIC _________________
print('\nStart removing benign instances')
t0 = time.time()
for index in df.index:
    if index % 1000 == 0:
        print('1000 rows treated in {} seconds'.format(time.time() - t0))
        t0 = time.time()
    if df['label'][index] == 'BENIGN':
        r = random.randint(0, 7)
        if r != 0:
            df.drop(index)
            # print('BENIGN DROPED')
print('Datframe after removing benign traffic\n', df)
df.to_csv('balanced_dataset.csv')


# PRINT DATASET FEATURES NAMES ____________________
nb_features = 0
for col in df.columns:
    nb_features += 1
    # print(col)
print('Nb of features:', nb_features)

# ONE-HOT ENCODING THEN CREATING TRAINING AND TESTING SAMPLES ________________________
X = df.iloc[:, 0:-1]
Y = df['label']  # Labels

X_encoded = pd.get_dummies(X, columns=['proto'])
print("One-hot encoding performed")

X_train, X_test, Y_train, Y_test = train_test_split(X_encoded, Y, test_size=0.2)

"""
# AI MODEL USING RANDOM FOREST CLASSIFIER ____________________________________
# Create a Gaussian Classifier
clf_Random_Forest = RandomForestClassifier(n_estimators=100)

# Train the model using the training sets y_pred=clf.predict(X_test)
clf_Random_Forest.fit(X_train, Y_train)
Y_pred = clf_Random_Forest.predict(X_test)

# Model Accuracy, how often is the classifier correct?
accuracy_all_features = metrics.accuracy_score(Y_test, Y_pred)
print("Accuracy:", accuracy_all_features)
"""

# PERFORM RECURSIVE FEATURES ELIMINATION _____________________
print('\nStart performing rfecv')
start_time_rfecv = time.time()
min_features_to_select = 1  # Minimum number of features to consider
rfecv = RFECV(
    estimator=RandomForestClassifier(n_estimators=100),
    step=1,
    cv=StratifiedKFold(2),
    scoring="accuracy",
    min_features_to_select=min_features_to_select)
rfecv.fit(X_encoded, Y)

X_rfe = rfecv.transform(X_encoded)
print("Num Features Before:", X_encoded.shape[1])
print("Num Features After:", X_rfe.shape[1])

features_kept = pd.DataFrame({'columns': X_encoded.columns, 'Kept': rfecv.support_})
print('Features kept :\n', features_kept)

X_new_df = X_encoded.iloc[:, rfecv.support_]
X_new_df.to_csv('dataset_rfe.csv')

print('Performing rfecv took {} seconds'.format(time.time() - start_time_rfecv))



print('\nRunning dataset script took {} seconds'.format(time.time() - start_time))