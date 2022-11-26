import os
import glob
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import HistGradientBoostingClassifier

import parse

"""
# TO WORK WITH PCAP FILES _____________________________________
df = parse.df_biflow
print(df)
"""


# TO WORK WITH CSV FILES __________________________________________
# Concat all csv files in a dataframe
df =pd.read_csv('dataset.csv')


"""
# LIST THE DIFFERENT TYPES OF ATTACKS IN DATASET __________________
attacks_list = []
for attack_type in df[' Label']:
    if not (attack_type in attacks_list):
        attacks_list.append(attack_type)
print("All classes for AI model : ", attacks_list)
"""

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

# PRINT DATASET FEATURES NAMES ____________________
for col in df.columns:
    print(col)



# ONE-HOT ENCODING THEN CREATING TRAINING AND TESTING SAMPLES ________________________
X = df.iloc[:, 0:-1]
Y = df['label']  # Labels
print(X)
print(Y)
# X.dropna()
# X.fillna(X.mean(), inplace=True)

X_encoded = pd.get_dummies(X, columns=['proto'])
print("One-hot encoding performed \n")

X_train, X_test, Y_train, Y_test = train_test_split(X_encoded, Y, test_size=0.2)

# AI MODEL USING HIST GRADIENT BOOSTING CLASSIFIER ___________________________
clf_hgbc = HistGradientBoostingClassifier().fit(X_train, Y_train)
print("Training performed\n")
print("Accuracy on train sample : ", clf_hgbc.score(X_train, Y_train))
print("Accuracy on test sample : ", clf_hgbc.score(X_test, Y_test))


"""
# AI MODEL USING RANDOM FOREST CLASSIFIER ____________________________________
# Create a Gaussian Classifier
clf_Random_Forest = RandomForestClassifier(n_estimators=100)

# Train the model using the training sets y_pred=clf.predict(X_test)
clf_Random_Forest.fit(X_train, Y_train)
Y_pred = clf_Random_Forest.predict(X_test)

Model Accuracy, how often is the classifier correct?
print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
"""
