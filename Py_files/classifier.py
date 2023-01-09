import pandas as pd
from keras import models, layers, utils, backend as K
import matplotlib.pyplot as plt
from imblearn.under_sampling import RandomUnderSampler
from sklearn.model_selection import train_test_split

from visualization import visualize_nn

# DeepNN
### layer input
n_features = 32
inputs = layers.Input(name="input", shape=(n_features,))  ### hidden layer 1
h1 = layers.Dense(name="h1", units=int(round((n_features + 1) / 2)), activation='relu')(inputs)
h1 = layers.Dropout(name="drop1", rate=0.2)(h1)  ### hidden layer 2
h2 = layers.Dense(name="h2", units=int(round((n_features + 1) / 4)), activation='relu')(h1)
h2 = layers.Dropout(name="drop2", rate=0.2)(h2)  ### layer output
outputs = layers.Dense(name="output", units=1, activation='sigmoid')(h2)

model = models.Model(inputs=inputs, outputs=outputs, name="DeepNN")
model.summary()

# visualize_nn(model, description=True, figsize=(10, 8))


# define metrics
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

# define metrics
def R2(y, y_hat):
    ss_res =  K.sum(K.square(y - y_hat))
    ss_tot = K.sum(K.square(y - K.mean(y)))
    return ( 1 - ss_res/(ss_tot + K.epsilon()) )


# compile the neural network
model.compile(optimizer='adam', loss='binary_crossentropy',
              metrics=['accuracy', F1])

"""
x = np.random.rand(1000,10)
y = np.random.choice([1,0], size=1000)
"""

df = pd.read_csv('binary_dataset2.csv').iloc[400000:500000]
print(df['label'].value_counts())

# REMOVE SOME FEATURES ___________________________
df.drop('Unnamed: 0', axis=1, inplace=True)
df.drop('Unnamed: 0.1', axis=1, inplace=True)

X = df.iloc[:, 0:-1]
Y = df['label']  # Labels


X_encoded = pd.get_dummies(X, columns=['proto'])
print("One-hot encoding performed")


X_train, X_test, Y_train, Y_test = train_test_split(X_encoded, Y, test_size=0.2)
print("Dataset has been split")


under = RandomUnderSampler(sampling_strategy=1)
X_smote, y_smote = under.fit_resample(X_train, Y_train)
print('RandomUnderSampler performed')
print(y_smote.value_counts())

x = X_smote.values
y = y_smote.values

# train/validation
training = model.fit(x=x, y=y, batch_size=32, epochs=50, shuffle=True, verbose=0, validation_data=(X_test, Y_test))
# plot
metrics = [k for k in training.history.keys() if ("loss" not in k) and ("val" not in k)]
# fig, ax = plt.subplots(nrows=1, ncols=2, sharey=True, figsize=(15, 3))

fig, axs = plt.subplots(1, 2)

axs[0].plot(training.history['loss'], label='Error (training data)')
axs[0].plot(training.history['val_loss'], label='Error (validation data)')
axs[0].set(title='Binary cross entropy loss function')
axs[0].set_ylabel('Loss Error')
axs[0].set_xlabel('No. epoch')
axs[0].legend(loc="upper right")
axs[0].grid()

axs[1].plot(training.history[metrics[0]], label='Accuracy (training data)')
axs[1].plot(training.history['val_' + metrics[0]], label='Accuracy (validation data)')
axs[1].set(title='Accuracy on the model')
axs[1].set_ylabel('Accuracy')
axs[1].set_xlabel('No. epoch')
axs[1].legend(loc="upper right")
axs[1].grid()
plt.show()

"""
print(metrics)
## training
ax[0].set(title="Training")
ax11 = ax[0].twinx()
ax[0].plot(training.history['loss'], color='black')
ax[0].set_xlabel('Epochs')
ax[0].set_ylabel('Loss', color='black')
# for metric in metrics:
ax11.plot(training.history[metrics[0]], label=metrics[0])
ax11.set_ylabel("Score", color='steelblue')
ax11.legend()


## validation
ax[1].set(title="Validation")
ax22 = ax[1].twinx()
ax[1].plot(testing.history['val_loss'], color='black')
ax[1].set_xlabel('Epochs')
ax[1].set_ylabel('Loss', color='black')
#for metric in metrics:
ax22.plot(training.history['val_' + metrics[0]], label=metrics[0])
ax22.set_ylabel("Score", color="steelblue")

plt.show()
"""