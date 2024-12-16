dict1_str = input()
dict2_str = input()

dict1 = eval(dict1_str)
dict2 = eval(dict2_str)

merged_dict = dict1.copy()
merged_dict.update(dict2)

print(merged_dict)