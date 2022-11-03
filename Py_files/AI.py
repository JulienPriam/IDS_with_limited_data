import os
import glob
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import HistGradientBoostingClassifier

import parse


# TO WORK WITH PCAP FILES _____________________________________
df = parse.df_biflow
print(df)


"""
# TO WORK WITH CSV FILES __________________________________________
# Concat all csv files in a dataframe
os.chdir("/home/eii/Documents/Strathclyde/archive/MachineLearningCSV/MachineLearningCVE/")
all_filenames = [i for i in glob.glob('*.{}'.format('csv'))]
df = pd.concat([pd.read_csv(f) for f in all_filenames])
print("Number of samples : ", len(df.index))
"""

"""
# LIST THE DIFFERENT TYPES OF ATTACKS IN DATASET __________________
attacks_list = []
for attack_type in df[' Label']:
    if not (attack_type in attacks_list):
        attacks_list.append(attack_type)
print("All classes for AI model : ", attacks_list)
"""

# PRINT DATASET FEATURES NAMES ____________________
for col in df.columns:
    print(col)



# ONE-HOT ENCODING THEN CREATING TRAINING AND TESTING SAMPLES ________________________
X = df.iloc[:, 0:-1]
# X.drop(' Destination Port', axis=1, inplace=True)  # TO DISCUSS
Y = df[' Label']  # Labels
# X.dropna()
# X.fillna(X.mean(), inplace=True)

"""
df_pandas_one_hot = pd.get_dummies(X,
                                   columns=['Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags',
                                            ' Bwd URG Flags',
                                            'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets',
                                            ' Subflow Bwd Bytes',
                                            'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd'])
print("One-hot encoding performed \n")
"""

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2)

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
