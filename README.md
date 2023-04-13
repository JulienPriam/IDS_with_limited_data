# AI (Machine Learning) for Intrusion Detection System using Limited Data


## Context
The need for efficient Intrusion Detection Systems (IDS) is a modern problem related to the rise of internet use, that aims to keep communication networks operational and secure. The present study focuses on improving IDS by using Machine Learning (ML) models that can be trained with limited data. Indeed, examples of attacks are not always sufficiently available which causes many problems for ML models training. The project is based on the CICIDS2017 dataset to train and test the developed models. This dataset contains 14 different types of malicious traffic associated with benign traffic, and 38 features related to the flows characteristics were extracted to perform classification using a feed forward Neural Network (NN).  
The problem has been approached step by step starting with binary classification that distinguishes benign from malicious traffic and which provides accurate results. However, the need for classifying types of malicious traffic has led the NN to evolve to multi-class classification. While the model performed well on classes containing many samples, its performances dropped drastically when integrating the underrepresented classes of the dataset (less than 200 samples per class).  
A solution to this problem has been tested with Siamese Networks which are particularly efficient when dealing with limited data. Indeed, Siamese Networks deal with pairs of samples rather than unique samples, and a huge number of different pairs can be created from a small set of samples. Associated with a K-Nearest Neighbours algorithm, the Siamese Network could perform better than a feed forward NN and finally, with only 80 samples per class and 13 classes, the model achieved 75% accuracy.  


## Join the project

### Installation
Clone the repository.  
You will need to install the following Python libraries:  
* dpkt
* datetime
* time
* numpy
* pandas
* imblearn
* Keras
* matplotlib
* sklearn
* seaborn
* pickle

The dataset CICIDS2017 is used for this project. It can be dowloaded on [this site](https://www.unb.ca/cic/datasets/ids-2017.html). Make sure to download the dataset in pcap format (5 files).  
Attention: each file of the dataset is around 10Gb. You will require quite a lot of free storage.  


### Compilation
The project contains 4 major scripts: one parser, one script that performs binary classification, one script that performs multi-class classification and one script that deals with limited data using a Siamese Neural Network.

1. The first file that needs to be run is the [features_extraction.py](Py_files/features_extraction.py) script.  
Make sure you uptade the SCRIPT PARAMETERS at top of file with the link to your dataset. Several other parameters help you to choose the actions that you want to perform.
2. [classifier_bin.py](Py_files/classifier_bin.py) allows you to perfrom binary classification
3. [classifier_multi.py](Py_files/classifier_multi.py) allows you to perform multi-class classification
4. [classifier_siamese.py](Py_files/classifier_siamese.py) allows you to perform multi-class classification using a Siamese Network and a K-Nearest Neighbours algorithm. This model improves the performances of the classifier when dealing with few samples (down to 25 samples per class).


## Credits
***
This AI has been developed by Julien Priam during a research project at University of Strathclyde.  
I thank Dr Robert Atkinson (University of Strathclyde, Glasgow) who supervised and guided the project throughout the year. I also thank Jack Wilkie and Christopher Mackinnon (PhD students) who attended every meeting and gave advice on the issues faced.
