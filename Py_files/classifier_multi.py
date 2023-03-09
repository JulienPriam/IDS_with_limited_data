import keras.optimizers
import pandas as pd
from keras import models, layers, utils, backend as K
import matplotlib.pyplot as plt
from imblearn.under_sampling import RandomUnderSampler
from keras.saving.legacy.model_config import model_from_json
from keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV, KFold, StratifiedKFold
from sklearn.metrics import confusion_matrix
import numpy as np
import seaborn as sn

from visualization import visualize_nn

# SCRIPT PARAMETERS ____________________________________________________________________________________________________
run_param_optimization = False  # perform RandomSearchCV
run_NN = True  # train and test the neural network
plot_network = True  # plot a view of the NN (not advised if RandomSearchCV performing)
save_model = True  # save the model structure and parameters on the disk / only works if run_NN = True
load_model = False  # load model from disk and evaluate it on testing set

# hyperparameters tuning
output_size = 13
layer1_neurons = 60
layer2_neurons = 30
batch_size = 128
epochs = 600
learning_rate = 0.0001
optimizer = keras.optimizers.Adam(learning_rate=learning_rate)

# for randomizedSearchCV
parameters = {'batch_size': [128],
              'nb_epoch': [100],
              'learning_rate': [0.001, 0.005, 0.01, 0.05, 0.1],
              'layer1_neurons': [5, 10, 15, 20, 25, 30],
              'layer2_neurons': [5, 10, 15, 20, 25, 30]}
n_iter = 100
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


# BUILD MODEL __________________________________________________________________________________________________________
def build_classifier(layer1_neurons, layer2_neurons, learning_rate):
    n_features = 30
    inputs = layers.Input(name="input", shape=(n_features,))  # hidden layer 1
    h1 = layers.Dense(name="h1", units=layer1_neurons, activation='relu')(inputs)
    # h1 = layers.Dropout(name="drop1", rate=0.2)(h1)  # hidden layer 2
    h2 = layers.Dense(name="h2", units=layer2_neurons, activation='relu')(h1)
    # h3 = layers.Dense(name="h3", units=20, activation='relu')(h2)
    # h4 = layers.Dense(name="h4", units=10, activation='relu')(h3)
    # h2 = layers.Dropout(name="drop2", rate=0.2)(h2)  ### layer output
    outputs = layers.Dense(name="output", units=output_size, activation='softmax')(h2)

    model = models.Model(inputs=inputs, outputs=outputs, name="DeepNN")
    model.summary()

    if plot_network:
        visualize_nn(model, description=True, figsize=(10, 8))


    model.compile(optimizer=optimizer, loss='categorical_crossentropy',
                  metrics=['accuracy'])
    return model


# ______________________________________________________________________________________________________________________


# PREPARE THE DATASET __________________________________________________________________________________________________
df = pd.read_csv('dataset_multi.csv') #.iloc[0:300000]
print(df['label'].value_counts())

# REMOVE SOME FEATURES ___________________________
df.drop('Unnamed: 0', axis=1, inplace=True)

print(df)

X = df.iloc[:, 0:-1]
Y = df['label']  # Labels
Y = pd.get_dummies(Y, columns=['label'])

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)
X_train, X_validation, y_train, y_validation = train_test_split(X_train, y_train, test_size=0.2)
print("Dataset has been split")

print('\n Partition of dataset:')
print('Number of samples per class in training set: \n{}'.format(y_train.value_counts()))
print('Number of samples per class in validation set: \n{}'.format(y_validation.value_counts()))
print('Number of samples per class in validation set: \n{} \n'.format(y_test.value_counts()))

X_train = X_train.values
y_train = y_train.values
X_validation = X_validation.values
y_validation = y_validation.values
X_test = X_test.values
y_test = y_test.values
# ______________________________________________________________________________________________________________________


# SEARCH FOR BEST HYPERPARAMETERS ______________________________________________________________________________________
if run_param_optimization:
    classifier = KerasClassifier(build_fn=build_classifier)
    random_search = RandomizedSearchCV(estimator=classifier, param_distributions=parameters,
                                       n_iter=n_iter, n_jobs=-1, cv=5)
    random_search.fit(X_train, y_train)

    # update hyperparameters with best values
    best_param = random_search.best_params_
    layer1_neurons = best_param['layer1_neurons']
    layer2_neurons = best_param['layer2_neurons']
    batch_size = best_param['batch_size']
    epochs = best_param['nb_epoch']
    learning_rate = best_param['learning_rate']

    # print the results
    print('\nHyperparameters optimization has been performed:')
    print('Random Best score', random_search.best_score_)
    print('Random Best params', best_param)
    print('Random execution time', random_search.refit_time_)
# ______________________________________________________________________________________________________________________


# TRAIN THE NEURAL NETWORK _____________________________________________________________________________________________
if run_NN:
    print('\nThe Neural Network will be trained with these parameters :')
    print('Layer1: {} neurons, layer2: {} neurons, batch size: {}, epochs: {}, learning rate {}'.format(layer1_neurons,
                                                                                                        layer2_neurons,
                                                                                                        batch_size,
                                                                                                        epochs,
                                                                                                        learning_rate))

    model = build_classifier(layer1_neurons, layer2_neurons, learning_rate)

    # train/validation _________________________________________________________________________________________________
    training = model.fit(x=X_train, y=y_train, batch_size=batch_size, epochs=epochs, shuffle=True, verbose=0,
                         validation_data=(X_validation, y_validation))
    testing = model.evaluate(X_validation, y_validation, batch_size=100)
    # __________________________________________________________________________________________________________________

    # PRINT RESULTS ____________________________________________________________________________________________________
    # plot
    metrics = [k for k in training.history.keys() if ("loss" not in k) and ("val" not in k)]
    fig, ax = plt.subplots(nrows=1, ncols=2, sharey=True, figsize=(15, 3))

    # Training
    ax[0].set(title="Training")
    ax[0].set_ylim(0, 10)
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

    # print confusion matrix
    #Predict
    y_prediction = model.predict(X_validation)
    y_prediction = np.argmax(y_prediction, axis = 1)
    y_validation=np.argmax(y_validation, axis=1)
    #Create confusion matrix and normalizes it over predicted (columns)
    result = confusion_matrix(y_validation, y_prediction , normalize='pred')
    df_cm = pd.DataFrame(result, range(output_size), range(output_size))
    # plt.figure(figsize=(10,7))
    sn.set(font_scale=1) # for label size
    sn.heatmap(df_cm, annot=True, annot_kws={"size": 12}) # font size

    plt.show()
    # __________________________________________________________________________________________________________________
# ______________________________________________________________________________________________________________________


# SAVE THE MODEL _______________________________________________________________________________________________________
if save_model & run_NN:
    # serialize model to JSON
    model_json = model.to_json()
    with open("model_multi.json", "w") as json_file:
        json_file.write(model_json)
    # serialize weights to HDF5
    model.save_weights("model_multi.h5")
    print("\nSaved model to disk")
# ______________________________________________________________________________________________________________________


# LOAD MODEL FROM DISK AND EVALUATE ON TESTING SET _____________________________________________________________________
if load_model:
    # load json and create model
    json_file = open('model_multi.json', 'r')
    loaded_model_json = json_file.read()
    json_file.close()
    loaded_model = model_from_json(loaded_model_json)
    # load weights into new model
    loaded_model.load_weights("model_multi.h5")
    print("\nLoaded model from disk")

    # evaluate loaded model on test data
    loaded_model.compile(optimizer=optimizer, loss='binary_crossentropy', metrics=['accuracy', F1])
    score = loaded_model.evaluate(X_test, y_test, verbose=0)
    print("{}: {}%".format(loaded_model.metrics_names[1], score[1] * 100))

    # print confusion matrix
    #Predict
    y_prediction = loaded_model.predict(X_test)
    y_prediction = np.argmax(y_prediction, axis = 1)
    y_test=np.argmax(y_test, axis=1)
    #Create confusion matrix and normalizes it over predicted (columns)
    result = confusion_matrix(y_test, y_prediction , normalize='pred')
    df_cm = pd.DataFrame(result, range(output_size), range(output_size))
    # plt.figure(figsize=(10,7))
    sn.set(font_scale=1) # for label size
    sn.heatmap(df_cm, annot=True, annot_kws={"size": 12}) # font size

    plt.show()
    # ______________________________________________________________________________________________________________________

