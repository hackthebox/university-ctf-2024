signals = input()
weights = input()

signals = list(map(int, signals.strip('[]').split(',')))
weights = list(map(int, weights.strip('[]').split(',')))

modified_signals = [signal * weight for signal, weight in zip(signals, weights)]

max_product = modified_signals[0]
min_product = modified_signals[0]
result = modified_signals[0]

for i in range(1, len(modified_signals)):
    num = modified_signals[i]

    if num < 0:
        max_product, min_product = min_product, max_product

    max_product = max(num, num * max_product)
    min_product = min(num, num * min_product)

    result = max(result, max_product)

print(result)
