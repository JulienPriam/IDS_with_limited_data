import numpy as np
import pandas as pd

from tensorflow import keras

from keras.models import Model
from keras.layers import Input, Lambda
from keras import models, layers, backend as K
from keras.saving.legacy.model_config import model_from_json

from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn import metrics


# SCRIPT PARAMETERS ____________________________________________________________________________________________________
run_NN = False  # train the neural network
load_model_multi = False  # load feed forward NN model from disk and use it as a base for siamese network
save_model = False  # save the model structure and parameters on the disk (only works if run_NN = True)
test_siamese = False  # Use the trained siamese network to predict the testing samples classes

# hyperparameters tuning
input_size = 38
output_size = 13
layer1_neurons = 30
layer2_neurons = 25
batch_size = 128
epochs = 25
learning_rate = 0.0001
optimizer = keras.optimizers.Adam(learning_rate=learning_rate)

nb_pairs_testing = 3
nb_associations_each_pair = 50
n_neighbors_train = 3
n_neighbors_test = 3
# ______________________________________________________________________________________________________________________


# PREPARE THE DATASET __________________________________________________________________________________________________
df = pd.read_csv('dataset_multi.csv')
df.drop('Unnamed: 0', axis=1, inplace=True)
print('Number of samples per class: \n', df['label'].value_counts())

X = df.iloc[:, 0:-1]
Y = df['label']  # Labels
# Y = pd.get_dummies(Y, columns=['label'])

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)
X_train, X_validation, y_train, y_validation = train_test_split(X_train, y_train, test_size=0.2)
print("\nDataset has been split as follow: ")
print('Number of samples per class in training set: \n{}'.format(y_train.value_counts()))
print('Number of samples per class in validation set: \n{}'.format(y_validation.value_counts()))
print('Number of samples per class in testing set: \n{} \n'.format(y_test.value_counts()))

X_train = X_train.values
y_train = y_train.values
X_validation = X_validation.values
y_validation = y_validation.values
X_test = X_test.values
y_test = y_test.values
# ______________________________________________________________________________________________________________________


def create_pairs(X, y, min_equals = 100):
    pairs = []
    labels = []
    equal_items = 0
    
    #index with all the positions containing a same value
    # Index[1] all the positions with values equals to 1
    # Index[2] all the positions with values equals to 2
    #.....
    # Index[9] all the positions with values equals to 9 
    index = [np.where(y == i)[0] for i in range(13)]
    
    for n_item in range(len(X)): 
        num_item_pair = []
        num_rnd = []
        if equal_items < min_equals:
            #Select the number to pair from index containing equal values. 
            for i in range(nb_associations_each_pair):
                num_rnd.append(np.random.randint(len(index[y[n_item]])))
                num_item_pair.append(index[y[n_item]][num_rnd[i]])

            equal_items += 1
        else: 
            #Select any number in the list 
            for i in range(nb_associations_each_pair):
                num_item_pair.append(np.random.randint(len(y)))

        #label depends on the fact that values are equal (1 if same class, 0 other)
        for i in range(nb_associations_each_pair):
            labels += [int(y[n_item] == y[num_item_pair[i]])]
            pairs += [[X[n_item], X[num_item_pair[i]]]]

    return np.array(pairs), np.array(labels).astype('float32')



training_pairs, training_labels = create_pairs(X_train, y_train, min_equals=int(len(y_train)/5))
val_pairs, val_labels = create_pairs(X_validation, y_validation, min_equals=int(len(y_validation)/5))
print('\nNumber of pairs in training set: ', len(training_labels))
print('Labels partition: ', np.unique(training_labels, return_counts=True))



def euclidean_distance(vects):
    x, y = vects
    sum_square = K.sum(K.square(x - y), axis=1, keepdims=True)
    return K.sqrt(K.maximum(sum_square, K.epsilon()))


def eucl_dist_output_shape(shapes):
    shape1, shape2 = shapes
    return (shape1[0], 1)


def contrastive_loss_with_margin(margin):
    def contrastive_loss(y_true, y_pred):
        square_pred = K.square(y_pred)
        margin_square = K.square(K.maximum(margin - y_pred, 0))
        return (y_true * square_pred + (1 - y_true) * margin_square)
    return contrastive_loss


def initialize_base_branch():
 
    if load_model_multi:
        # load json and create model
        json_file = open('model_multi.json', 'r')
        loaded_model_json = json_file.read()
        json_file.close()
        model = model_from_json(loaded_model_json)
        # load weights into new model
        model.load_weights("model_multi.h5")
        print("\nLoaded model from disk")

    else: 
        inputs = layers.Input(name="input", shape=(input_size,))  # hidden layer 1
        h1 = layers.Dense(name="h1", units=layer1_neurons, activation='relu')(inputs)
        h2 = layers.Dense(name="h2", units=layer2_neurons, activation='relu')(h1)
        outputs = layers.Dense(name="output", units=output_size, activation='softmax')(h2)

        model = models.Model(inputs=inputs, outputs=outputs, name="DeepNN")
        model.summary()

    #Returning a Model, with input and outputs, not just a group of layers. 
    return model


#A difference less than 0.5 means the pair images are the same type
def compute_accuracy(y_true, y_pred):
    pred = y_pred.ravel() < 0.5
    return np.mean(pred == y_true)


# TRAIN THE NEURAL NETWORK _____________________________________________________________________________________________
if run_NN:
    base_model = initialize_base_branch()

    #Input for the left part of the pair. We are going to pass training_pairs[:,0] to his layer. 
    input_l = Input((input_size,), name='left_input')
    vect_output_l = base_model(input_l)

    #Input layer for the right part of the siamse model. Will receive: training_pairs[:,1]
    input_r = Input((input_size,), name='right_input')
    vect_output_r = base_model(input_r)

    #The lambda output layer calling the euclidenan distances, will return the difference between both vectors
    output = Lambda(euclidean_distance, name='output_layer', 
                    output_shape=eucl_dist_output_shape)([vect_output_l, vect_output_r])

    #Our model have two inputs and one output. Each of the inputs contains the commom model. 
    model = Model([input_l, input_r], output)

 
    model.compile(loss=contrastive_loss_with_margin(margin=1),
                    optimizer=optimizer)

    history = model.fit(
            [training_pairs[:,0], training_pairs[:,1]], 
            training_labels, epochs=epochs, 
            batch_size=batch_size, 
            validation_data = ([val_pairs[:, 0], val_pairs[:, 1]], val_labels))


    y_pred_train = model.predict([training_pairs[:,0], training_pairs[:,1]])
    train_accuracy = compute_accuracy(training_labels, y_pred_train)

    y_pred_val = model.predict([val_pairs[:,0], val_pairs[:,1]])
    val_accuracy = compute_accuracy(val_labels, y_pred_val)

    print("Train Accuracy = {} Val accuracy = {}".format(train_accuracy, val_accuracy))
# ______________________________________________________________________________________________________________________


# SAVE THE MODEL _______________________________________________________________________________________________________
if save_model & run_NN:
    # serialize model to JSON
    model_json = model.to_json()
    with open("model_siamese.json", "w") as json_file:
        json_file.write(model_json)
    # serialize weights to HDF5
    model.save_weights("model_siamese.h5")
    print("\nSaved model to disk")
# ______________________________________________________________________________________________________________________


# LOAD MODEL FROM DISK AND EVALUATE ON TESTING SET _____________________________________________________________________
def create_testing_pairs(X_test, X_train, neighbors_list):
    pairs = []

    for n_item in range(len(X_test)):
        pairs_sample = []
        for sample in range(n_neighbors_test):
            num_item_pair = neighbors_list[n_item][sample]
            pairs_sample += [[X_test[n_item], X_train[num_item_pair]]]
        pairs.append(pairs_sample)

    return np.array(pairs)


def compute_test_accuracy(y_pred, y_real):
    n = len(y_pred)
    correct = 0
    for i in range(n):
        if y_pred[i] == y_real[i]:
            correct += 1
    return correct/n


if test_siamese:

    # Define a KNN to get the nearest neighbors of the testing samples
    knn = KNeighborsClassifier(n_neighbors=n_neighbors_train)
    knn.fit(X_train, y_train)
    y_predict = knn.predict(X_test)

    print('\nKNN accuracy on testing set: ', metrics.accuracy_score(y_test, y_predict))

    # get the n_neighbors_test closest point of each sample
    test_samples_neighbors = []
    for i in range(len(X_test)):
        neighbors = knn.kneighbors([X_test[i]], n_neighbors=n_neighbors_test)
        list_temp = []
        for j in range(n_neighbors_test):
            list_temp.append(neighbors[1][0][j])
        test_samples_neighbors.append(list_temp)

    # create the testing pairs based on the closest point
    testing_pairs = create_testing_pairs(X_test, X_train, test_samples_neighbors)
    
    # load json and create siamese model
    json_file = open('model_siamese.json', 'r')
    loaded_model_json = json_file.read()
    json_file.close()
    model = model_from_json(loaded_model_json)
    # load weights into the model
    model.load_weights("model_siamese.h5")
    print("\nLoaded model from disk")

    model.compile(loss=contrastive_loss_with_margin(margin=1),
                    optimizer=optimizer)
    
    # make the prediction for each sample
    y_pred_testing = []
    for sample in range(len(testing_pairs)):  # len(testing_pairs)
        proba_per_class_mean = []
        proba_per_class = []
        for k in range(output_size):
            proba_per_class.append([])
        predicted_proba = model.predict([testing_pairs[sample][:,0], testing_pairs[sample][:,1]])
        predicted_proba = list(np.concatenate(predicted_proba).flat)
        
        for i in range(len(predicted_proba)):
            _class = y_train[test_samples_neighbors[sample][i]]
            proba_per_class[_class].append(predicted_proba[i])
        for i in range(len(proba_per_class)):
            if proba_per_class[i] == []:
                proba_per_class_mean.append(1000)
            else:
                proba_per_class_mean.append(np.mean(proba_per_class[i]))
        y_pred_testing.append(np.argmin(proba_per_class_mean))

    # compute the testing accuracy and display the result
    testing_accuracy = compute_test_accuracy(y_pred_testing, y_test)
    print("Test Accuracy = {}".format(testing_accuracy))
        
# ______________________________________________________________________________________________________________________
