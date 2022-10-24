import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import make_column_transformer
from sklearn import metrics

from parse import parse_pcap
from parse import parse_pcap_csv

# df_pcap = parse_pcap(10000)
# print(df_pcap)

df_csv = parse_pcap_csv()
print("Number of samples : ", len(df_csv.index))
# print(df_csv)

"""
# PRINT DATASET FEATURES NAMES ____________________
for col in df_csv.columns:
    print(col)
"""


# ONE-HOT ENCODING THEN CREATING TRAINING AND TESTING SAMPLES ________________________
X = df_csv.iloc[:, 0:-1]
X.drop(' Destination Port', axis=1, inplace=True)   # TO DISCUSS
Y = df_csv[' Label']  # Labels
# X.dropna()
# X.fillna(X.mean(), inplace=True)

df_pandas_one_hot = pd.get_dummies(X,
                                   columns=['Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags',
                                            ' Bwd URG Flags',
                                            'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets',
                                            ' Subflow Bwd Bytes',
                                            'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd'])

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2)


# AI MODEL USING HIST GRADIENT BOOSTING CLASSIFIER ___________________________
clf_hgbc = HistGradientBoostingClassifier().fit(X_train, Y_train)
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


