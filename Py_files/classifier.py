import pandas as pd
from keras import models, layers, utils, backend as K
import matplotlib.pyplot as plt
from imblearn.under_sampling import RandomUnderSampler
from keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import train_test_split, GridSearchCV

from visualization import visualize_nn

# BUILD MODEL __________________________________________________________________________________________________________
n_features = 32
inputs = layers.Input(name="input", shape=(n_features,))  ### hidden layer 1
h1 = layers.Dense(name="h1", units=int(round((n_features + 1) / 2)), activation='relu')(inputs)
#h1 = layers.Dropout(name="drop1", rate=0.2)(h1)  ### hidden layer 2
h2 = layers.Dense(name="h2", units=int(round((n_features + 1) / 4)), activation='relu')(h1)
#h2 = layers.Dropout(name="drop2", rate=0.2)(h2)  ### layer output
outputs = layers.Dense(name="output", units=1, activation='sigmoid')(h2)

model = models.Model(inputs=inputs, outputs=outputs, name="DeepNN")
model.summary()

visualize_nn(model, description=True, figsize=(10, 8))
# ______________________________________________________________________________________________________________________


# DEFINE METRICS _______________________________________________________________________________________________________
def Recall(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
    recall = true_positives / (possible_positives + K.epsilon())
    return recall


def Precision(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
    precision = true_positives / (predicted_positives + K.epsilon())
    return precision


def F1(y_true, y_pred):
    precision = Precision(y_true, y_pred)
    recall = Recall(y_true, y_pred)
    return 2 * ((precision * recall) / (precision + recall + K.epsilon()))


def R2(y, y_hat):
    ss_res = K.sum(K.square(y - y_hat))
    ss_tot = K.sum(K.square(y - K.mean(y)))
    return (1 - ss_res / (ss_tot + K.epsilon()))
# ______________________________________________________________________________________________________________________


# COMPILE THE NEURAL NETWORK ___________________________________________________________________________________________
model.compile(optimizer='adam', loss='binary_crossentropy',
              metrics=['accuracy'])

#df = pd.read_csv('CIC_features_binary.csv').iloc[300000:500000]
df = pd.read_csv('binary_dataset2.csv').iloc[500000:550000]
print(df['label'].value_counts())

# REMOVE SOME FEATURES ___________________________
df.drop('Unnamed: 0', axis=1, inplace=True)
df.drop('Unnamed: 0.1', axis=1, inplace=True)

X = df.iloc[:, 0:-1]
Y = df['label']  # Labels

X_encoded = pd.get_dummies(X, columns=['proto'])
print("One-hot encoding performed")

X_train, X_test, y_train, y_test = train_test_split(X_encoded, Y, test_size=0.2)
print("Dataset has been split")

under = RandomUnderSampler(sampling_strategy=1)
X_smote_train, y_smote_train = under.fit_resample(X_train, y_train)
X_smote_test, y_smote_test = under.fit_resample(X_test, y_test)
print('\nRandomUnderSampler performed')
print(y_smote_train.value_counts())

X_train = X_smote_train.values
y_train = y_smote_train.values
X_test = X_smote_test.values
y_test = y_smote_test.values


# train/validation _____________________________________________________________________________________________________
training = model.fit(x=X_train, y=y_train, batch_size=100, epochs=100, shuffle=True, verbose=0, validation_split=0.2)
testing = model.evaluate(X_test, y_test, batch_size=100)
# ______________________________________________________________________________________________________________________


# PRINT RESULTS ________________________________________________________________________________________________________
# plot
metrics = [k for k in training.history.keys() if ("loss" not in k) and ("val" not in k)]
fig, ax = plt.subplots(nrows=1, ncols=2, sharey=True, figsize=(15, 3))

# Training
ax[0].set(title="Training")
ax11 = ax[0].twinx()
ax[0].plot(training.history['loss'], color='black')
ax[0].set_xlabel('Epochs')
ax[0].set_ylabel('Loss', color='black')
for metric in metrics:
    ax11.plot(training.history[metric], label=metric)
    ax11.set_ylabel("Score", color='steelblue')
ax11.legend()

# Validation
ax[1].set(title="Validation")
ax22 = ax[1].twinx()
ax[1].plot(training.history['val_loss'], color='black')
ax[1].set_xlabel('Epochs')
ax[1].set_ylabel('Loss', color='black')
for metric in metrics:
    ax22.plot(training.history['val_' + metric], label=metric)
    ax22.set_ylabel("Score", color="steelblue")
plt.show()
# ______________________________________________________________________________________________________________________