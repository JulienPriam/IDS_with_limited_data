#Import libraries. 

import numpy as np
import pandas as pd

from tensorflow import keras

from keras.models import Model
from keras.layers import Input, Lambda
from keras import models, layers, backend as K
from keras.saving.legacy.model_config import model_from_json

from sklearn.model_selection import train_test_split


# SCRIPT PARAMETERS ____________________________________________________________________________________________________
run_NN = False  # train and test the neural network
load_model_multi = False  # load feed forward NN model from disk and use it for siamese network
load_model_siamese = False  # load siamese NN model from disk (if both are true, the siamese network is used)
save_model = False  # save the model structure and parameters on the disk / only works if run_NN = True

# hyperparameters tuning
n_features = 30
output_size = 13
layer1_neurons = 30
layer2_neurons = 25
batch_size = 128
epochs = 300
learning_rate = 0.0001
optimizer = keras.optimizers.Adam(learning_rate=learning_rate)

nb_pairs_testing = 10
nb_associations_each_pair = 3
# ______________________________________________________________________________________________________________________

def show_pairs(X, y, image):
    print('\nDisplay of a pair generated')
    print(X[image][0])
    print(X[image][1])
    print(y[image])



# PREPARE THE DATASET __________________________________________________________________________________________________
df = pd.read_csv('dataset_multi.csv')
print('Number of samples per class: ', df['label'].value_counts())

# REMOVE SOME FEATURES ___________________________
df.drop('Unnamed: 0', axis=1, inplace=True)

print(df)

X = df.iloc[:, 0:-1]
Y = df['label']  # Labels
# Y = pd.get_dummies(Y, columns=['label'])

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)
X_train, X_validation, y_train, y_validation = train_test_split(X_train, y_train, test_size=0.2)
print("Dataset has been split")

# print('\n Partition of dataset:')
# print('Number of samples per class in training set: \n{}'.format(y_train.value_counts()))
# print('Number of samples per class in validation set: \n{}'.format(y_validation.value_counts()))
# print('Number of samples per class in validation set: \n{} \n'.format(y_test.value_counts()))

X_train = X_train.values
y_train = y_train.values
X_validation = X_validation.values
y_validation = y_validation.values
X_test = X_test.values
y_test = y_test.values
print("Number of samples in training set: ", len(y_train))
# ______________________________________________________________________________________________________________________




#The third parameter: min_equals. indicate how many equal pairs, as minimun, we want in the dataset. 
#If we just created random pairs the number of equal pairs would be very small. 
def create_pairs(X, y, min_equals = 200):
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

            """
            num_rnd1 = np.random.randint(len(index[y[n_item]]))
            num_rnd2 = np.random.randint(len(index[y[n_item]]))
            num_rnd3 = np.random.randint(len(index[y[n_item]]))
            num_item_pair1 = index[y[n_item]][num_rnd1]
            num_item_pair2 = index[y[n_item]][num_rnd2]
            num_item_pair3 = index[y[n_item]][num_rnd3]
            """

            equal_items += 1
        else: 
            #Select any number in the list 
            for i in range(nb_associations_each_pair):
                num_item_pair.append(np.random.randint(len(y)))
            
            """
            num_item_pair1 = np.random.randint(len(y))
            num_item_pair2 = np.random.randint(len(y))
            num_item_pair3 = np.random.randint(len(y))
            """

        #I'm not checking that numbers is different. 
        #That's why I calculate the label depending if values are equal. 
        for i in range(nb_associations_each_pair):
            labels += [int(y[n_item] == y[num_item_pair[i]])]
            pairs += [[X[n_item], X[num_item_pair[i]]]]
        """
        labels += [int(y[n_item] == y[num_item_pair1])]
        labels += [int(y[n_item] == y[num_item_pair2])]
        labels += [int(y[n_item] == y[num_item_pair3])]
        pairs += [[X[n_item], X[num_item_pair1]]]
        pairs += [[X[n_item], X[num_item_pair2]]]
        pairs += [[X[n_item], X[num_item_pair3]]]
        """
    return np.array(pairs), np.array(labels).astype('float32')



training_pairs, training_labels = create_pairs(X_train, y_train, min_equals=260)
val_pairs, val_labels = create_pairs(X_validation, y_validation, min_equals=80)
print('Number of pairs in training set: ', len(training_labels))


def create_testing_pairs(X, y):
    pairs = []
    
    #index with all the positions containing a same value
    # Index[1] all the positions with values equals to 1
    # Index[2] all the positions with values equals to 2
    #.....
    # Index[13] all the positions with values equals to 13
    index = [np.where(y == i)[0] for i in range(13)]
    
    for n_item in range(len(X)):
        one_sample_pairs = []
        for i in range(13):
            pairs_same_class = []
            offset = 0
            for j in range(nb_pairs_testing):
                if n_item == index[i][j]:
                    offset = 1
                num_item_pair = index[i][j + offset]
                pairs_same_class += [[X[n_item], X[num_item_pair]]]
            one_sample_pairs.append(pairs_same_class)
        pairs.append(one_sample_pairs)

    return np.array(pairs)

testing_pairs = create_testing_pairs(X_test, y_test)
print(testing_pairs[0][0])
print('\n\n SEPARATION \n\n')
print(testing_pairs[0][12])
print(len(testing_pairs))


"""
#Different pair of the training set labeled with a 0. 
show_pairs(training_pairs, training_labels, 500)

#Same pair of the training set labeled with a 1. 
show_pairs(training_pairs, training_labels, 100)

#Similar pair of the validation set labeled with a 1. 
show_pairs(val_pairs, val_labels, 10)

#Different pair of the validation set labeled with a 0. 
show_pairs(val_pairs, val_labels, 150)
"""


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
        inputs = layers.Input(name="input", shape=(n_features,))  # hidden layer 1
        h1 = layers.Dense(name="h1", units=layer1_neurons, activation='relu')(inputs)
        h2 = layers.Dense(name="h2", units=layer2_neurons, activation='relu')(h1)
        outputs = layers.Dense(name="output", units=output_size, activation='softmax')(h2)

        model = models.Model(inputs=inputs, outputs=outputs, name="DeepNN")
        model.summary()

    #Returning a Model, with input and outputs, not just a group of layers. 
    return model


#I m assuming that with a difference less than 0.5 the pair images are the same type
def compute_accuracy(y_true, y_pred):
    pred = y_pred.ravel() < 0.5
    return np.mean(pred == y_true)

# TRAIN THE NEURAL NETWORK _____________________________________________________________________________________________
if run_NN:
    base_model = initialize_base_branch()

    #Input for the left part of the pair. We are going to pass training_pairs[:,0] to his layer. 
    input_l = Input((n_features,), name='left_input')
    #ATENTION!!! base_model is not an function, is model and we are adding our input layer. 
    vect_output_l = base_model(input_l)

    #Input layer for the right part of the siamse model. Will receive: training_pairs[:,1]
    input_r = Input((n_features,), name='right_input')
    vect_output_r = base_model(input_r)

    #The lambda output layer calling the euclidenan distances, will return the difference between both vectors
    output = Lambda(euclidean_distance, name='output_layer', 
                    output_shape=eucl_dist_output_shape)([vect_output_l, vect_output_r])

    #Our model have two inputs and one output. Each of the inputs contains the commom model. 
    model = Model([input_l, input_r], output)


    #We use the 'Custom' loss function. And we can pass the margin. I'ts one of the variables
    #in the formula, and matain the balance between the value asigned when there arfe similarities or not. 
    #with a big value the dissimilarities have more wight than the similarities. 
    #you can try different values, I have the impression that we can increase the values and maybe improve 
    #a little bit the results. 
    #I choose to use an 1. Totally balanced. 
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
def compute_test_accuracy(y_pred, y_real):
    n = len(y_pred)
    correct = 0
    for i in range(n):
        if y_pred[i] == y_real[i]:
            correct += 1
    return correct/n

if load_model_siamese:
    # load json and create model
    json_file = open('model_siamese.json', 'r')
    loaded_model_json = json_file.read()
    json_file.close()
    model = model_from_json(loaded_model_json)
    # load weights into new model
    model.load_weights("model_siamese.h5")
    print("\nLoaded model from disk")

    model.compile(loss=contrastive_loss_with_margin(margin=1),
                    optimizer=optimizer)
    
    y_pred_testing = []
    for i in range(len(testing_pairs)):
        predicted_proba_mean = []
        for j in range(13):
            predicted_proba = model.predict([testing_pairs[i][j][:,0], testing_pairs[i][j][:,1]])
            predicted_proba_mean.append(np.mean(predicted_proba))
        y_pred_testing.append(np.argmin(predicted_proba_mean))
    print(y_pred_testing)

    testing_accuracy = compute_test_accuracy(y_pred_testing, y_test)

    print("Test Accuracy = {}".format(testing_accuracy))
# ______________________________________________________________________________________________________________________
