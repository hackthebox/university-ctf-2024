energy_crystals = input()
target_energy = input()

energy_crystals = list(map(int, energy_crystals.strip("[]").split(",")))
target_energy = int(target_energy)

dp = [0] * (target_energy + 1)
dp[0] = 1

for crystal in energy_crystals:
    for j in range(crystal, target_energy + 1):
        dp[j] += dp[j - crystal]

print(dp[target_energy])
