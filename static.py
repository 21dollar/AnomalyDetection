import pandas as pd
import numpy as np
import math
import time
from random import randint


def calc_entropy(column):
    counts = np.bincount(column)

    probabilities = counts / len(column)

    entropy = 0
    for prob in probabilities:
        if prob > 0:
            entropy += prob * math.log(prob, 2)  
    return -entropy

def calc_information_gain(data, split_name, target_name):
    original_entropy = calc_entropy(data[target_name])

    values = data[split_name].unique()

    ranges = [data[data[split_name] == value] for value in values]

    to_subtract = 0
    for subset in ranges:
        prob = (subset.shape[0] / data.shape[0]) 
        to_subtract += prob * calc_entropy(subset[target_name])

    return original_entropy - to_subtract



def highest_info_gain(midwest, columns, target_column):
    information_gains = {}

    for col in columns:
        information_gain = calc_information_gain(midwest, col, target_column)                                        
        information_gains[col] = information_gain                                   
    return max(information_gains, key=information_gains.get)



def make_tree(group, target_column, qvan):
    columns = group.columns[:-1]
    if len(columns) == 0 or calc_entropy(group[target_column]) < 0.01:
        return [group[target_column].value_counts().idxmax(), None]

    curname = highest_info_gain(group, columns, target_column)
    #print(ident*' ', curname)
    q = pd.qcut(group[curname].values, qvan, duplicates='drop')
    groups = group.groupby(q)
    #print(group[curname])
    group.pop(curname)
    tree = [curname, []]
    #print(groups.categories())
    for val, group in groups:
        #print(val)
        if not group.empty:
            #print(group[curname])
            tree[1].append([val, make_tree(group, target_column, qvan)])

    return tree


def print_tree(tree, group, ident = 0):
    clm, tree = tree
    if not tree:
        print(clm)
        print(group)
        return
    print(' '*ident, clm, sep='')
    for val, subtree in tree:
        print(' '*ident, '|---', val, sep='')
        print_tree(subtree, group[group[clm].between(val.left, val.right)], ident + 4)


def predict(record, tree):
    clm, categories = tree
    if categories is None:
        return clm
    for interval, tree in categories:
        if record[clm] in interval:
            return predict(record, tree)
    return None

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
        if datafame_test.iloc[k]['predicted'] == 1 and datafame_test.iloc[k]['Label'] == 1:
            class1_1 += 1
        if datafame_test.iloc[k]['predicted'] == 2 and datafame_test.iloc[k]['Label'] == 2:
            class2_2 += 1
        if datafame_test.iloc[k]['predicted'] == 0 and datafame_test.iloc[k]['Label'] == 1:
            class0_1 += 1
        if datafame_test.iloc[k]['predicted'] == 0 and datafame_test.iloc[k]['Label'] == 2:
            class0_2 += 1
        if datafame_test.iloc[k]['predicted'] == 1 and datafame_test.iloc[k]['Label'] == 0:
            class1_0 += 1
        if datafame_test.iloc[k]['predicted'] == 1 and datafame_test.iloc[k]['Label'] == 2:
            class1_2 += 1
        if datafame_test.iloc[k]['predicted'] == 2 and datafame_test.iloc[k]['Label'] == 0:
            class2_0 += 1
        if datafame_test.iloc[k]['predicted'] == 2 and datafame_test.iloc[k]['Label'] == 1:
            class2_1 += 1

    print('class0_0: ', class0_0)
    print('class0_1: ', class0_1)
    print('class0_2: ', class0_2)
    print('class1_0: ', class1_0)
    print('class1_1: ', class1_1)
    print('class1_2: ', class1_2)
    print('class2_0: ', class2_0)
    print('class2_1: ', class2_1)
    print('class2_2: ', class2_2)






datafame_train = pd.read_csv("train_mosaic.csv", nrows=200)
datafame_test = pd.read_csv("test_mosaic.csv", nrows=20)


print('Begin')

columns = ['apple_pie?', 'potato_salad?', 'sushi?']

labeled = {"BENIGN":0, "DoS Hulk":1, "DoS slowloris":2}

datafame_train['Label'] = [labeled[value] for value in datafame_train['Label']]
datafame_test['Label'] = [labeled[value] for value in datafame_test['Label']]

datafame_train.drop(columns=['Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags', 'CWE_Flag_Count', 'Fwd_Avg_Bytes_Bulk', 'Fwd_Avg_Packets_Bulk', 'Fwd_Avg_Bulk_Rate', 'Bwd_Avg_Bytes_Bulk', 'Bwd_Avg_Packets_Bulk', 'Bwd_Avg_Bulk_Rate'], inplace=True)
datafame_test.drop(columns=['Fwd_URG_Flags', 'Bwd_URG_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags', 'CWE_Flag_Count', 'Fwd_Avg_Bytes_Bulk', 'Fwd_Avg_Packets_Bulk', 'Fwd_Avg_Bulk_Rate', 'Bwd_Avg_Bytes_Bulk', 'Bwd_Avg_Packets_Bulk', 'Bwd_Avg_Bulk_Rate'], inplace=True)

datafame_train.drop(columns=['Total_Length_of_Bwd_Packets', 'Fwd_Packet_Length_Min', 'Bwd_Packet_Length_Max', 
    'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean', 'Bwd_Packet_Length_Std', 'Fwd_IAT_Std', 'Bwd_IAT_Total', 
    'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Min_Packet_Length', 'Down_Up_Ratio', 'Avg_Bwd_Segment_Size', 
    'Subflow_Bwd_Bytes', 'min_seg_size_forward', 'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min', 
    'Idle_Mean', 'Idle_Std', 'Idle_Max'], inplace=True)
datafame_test.drop(columns=['Total_Length_of_Bwd_Packets', 'Fwd_Packet_Length_Min', 'Bwd_Packet_Length_Max', 
    'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean', 'Bwd_Packet_Length_Std', 'Fwd_IAT_Std', 'Bwd_IAT_Total', 
    'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Min_Packet_Length', 'Down_Up_Ratio', 'Avg_Bwd_Segment_Size', 
    'Subflow_Bwd_Bytes', 'min_seg_size_forward', 'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min', 
    'Idle_Mean', 'Idle_Std', 'Idle_Max'], inplace=True)

datafame_train.drop(columns=['Total_Length_of_Fwd_Packets', 'Fwd_Packet_Length_Max', 'Fwd_Packet_Length_Mean', 'Fwd_Packet_Length_Std',
    'Flow_Bytes_Sec', 'Flow_IAT_Std', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_Header_Length',
    'Bwd_Packets_Sec', 'Max_Packet_Length', 'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance', 'Average_Packet_Size', 
    'Avg_Fwd_Segment_Size', 'Subflow_Fwd_Bytes', 'Subflow_Bwd_Packets', 'Init_Win_bytes_backward', 'act_data_pkt_fwd'], inplace=True)
datafame_test.drop(columns=['Total_Length_of_Fwd_Packets', 'Fwd_Packet_Length_Max', 'Fwd_Packet_Length_Mean', 'Fwd_Packet_Length_Std',
    'Flow_Bytes_Sec', 'Flow_IAT_Std', 'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_Header_Length',
    'Bwd_Packets_Sec', 'Max_Packet_Length', 'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance', 'Average_Packet_Size', 
    'Avg_Fwd_Segment_Size', 'Subflow_Fwd_Bytes', 'Subflow_Bwd_Packets', 'Init_Win_bytes_backward', 'act_data_pkt_fwd'], inplace=True)


target_column = datafame_train.columns[-1]


print('End drop')
start = time.perf_counter_ns()

TREE = make_tree(datafame_train.copy(), target_column, 4)
#print(datafame_train)
print_tree(TREE, datafame_train)
#print(TREE)
print('time make_tree: ', (time.perf_counter_ns() - start)/ 10**9)


print(predict(datafame_train.iloc[0], TREE))

datafame_test['predicted'] = pd.Series([predict(rec, TREE) for _, rec in datafame_test.iterrows()])

pred_matrix(datafame_test)



#print(datafame_test)
matches = (datafame_test[target_column] == datafame_test['predicted'])
print('accuracy:', matches.sum() / matches.size)
#print(matches)


