import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn import preprocessing
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

def pred_matrix(datafame_test):
    class0_0 = 0
    class0_1 = 0
    class0_2 = 0
    class1_0 = 0
    class1_1 = 0
    class1_2 = 0
    class2_0 = 0
    class2_1 = 0
    class2_2 = 0
    for k, frame in datafame_test.iterrows():
        if datafame_test.iloc[k]['predicted'] == 0 and datafame_test.iloc[k]['Label'] == 0:
            class0_0 += 1
        elif datafame_test.iloc[k]['predicted'] == 1 and datafame_test.iloc[k]['Label'] == 1:
            class1_1 += 1
        elif datafame_test.iloc[k]['predicted'] == 2 and datafame_test.iloc[k]['Label'] == 2:
            class2_2 += 1
        elif datafame_test.iloc[k]['predicted'] == 0 and datafame_test.iloc[k]['Label'] == 1:
            class0_1 += 1
        elif datafame_test.iloc[k]['predicted'] == 0 and datafame_test.iloc[k]['Label'] == 2:
            class0_2 += 1
        elif datafame_test.iloc[k]['predicted'] == 1 and datafame_test.iloc[k]['Label'] == 0:
            class1_0 += 1
        elif datafame_test.iloc[k]['predicted'] == 1 and datafame_test.iloc[k]['Label'] == 2:
            class1_2 += 1
        elif datafame_test.iloc[k]['predicted'] == 2 and datafame_test.iloc[k]['Label'] == 0:
            class2_0 += 1
        elif datafame_test.iloc[k]['predicted'] == 2 and datafame_test.iloc[k]['Label'] == 1:
            class2_1 += 1
        if k%10000 == 0:
            print(k)

    print('class0_0: ', class0_0)
    print('class0_1: ', class0_1)
    print('class0_2: ', class0_2)
    print('class1_0: ', class1_0)
    print('class1_1: ', class1_1)
    print('class1_2: ', class1_2)
    print('class2_0: ', class2_0)
    print('class2_1: ', class2_1)
    print('class2_2: ', class2_2)

datafame_train = pd.read_csv("train_mosaic.csv", nrows=100)
datafame_test = pd.read_csv("test_mosaic.csv", nrows=100)

datafame_train.drop(columns=['Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags', 'CWE_Flag_Count', 'Fwd_Avg_Bytes_Bulk', 'Fwd_Avg_Packets_Bulk', 'Fwd_Avg_Bulk_Rate', 'Bwd_Avg_Bytes_Bulk', 'Bwd_Avg_Packets_Bulk', 'Bwd_Avg_Bulk_Rate'], inplace=True)
datafame_test.drop(columns=['Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags', 'CWE_Flag_Count', 'Fwd_Avg_Bytes_Bulk', 'Fwd_Avg_Packets_Bulk', 'Fwd_Avg_Bulk_Rate', 'Bwd_Avg_Bytes_Bulk', 'Bwd_Avg_Packets_Bulk', 'Bwd_Avg_Bulk_Rate'], inplace=True)

classifier = LogisticRegression(solver='lbfgs',random_state=0)

classifier.fit(datafame_train.iloc[:,0:-1], datafame_train.iloc[:,-1])

predicted_y = classifier.predict(datafame_test.iloc[:,0:-1])

print(datafame_test)
print('Accuracy: {:.9f}'.format(classifier.score(datafame_test.iloc[:,0:-1], datafame_test.iloc[:,-1])))

datafame_test['predicted'] = predicted_y

labeled = {"BENIGN":0, "DoS Hulk":1, "DoS slowloris":2}
datafame_test['Label'] = [labeled[value] for value in datafame_test['Label']]
datafame_test['predicted'] = [labeled[value] for value in datafame_test['predicted']]

pred_matrix(datafame_test)