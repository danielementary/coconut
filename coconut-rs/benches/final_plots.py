import matplotlib as mpl
import matplotlib.pyplot as plt

# coconut: 10 validators, 7 threshold, 1 private attribute, 0 public attributes
x_values = [10, 50, 100, 500, 1000]

# no proof
none_issue = [0] * len(x_values)
none_issuance_size = [0] * len(x_values)
none_prove = [12.953] * len(x_values)
none_proof_size = [296] * len(x_values)
none_verify =[21.274] * len(x_values)

# set membership proof
set_issue = [31.093, 140.21, 238.06, 1219.2, 2364.2]
set_issuance_size = [value * 96 for value in x_values]
set_prove = [34.001, 35.050, 30.183, 33.375, 26.009]
set_proof_size = [680] * len(x_values)
set_verify = [45.731, 43.545, 37.656, 34.048, 35.564]

# range proof
range_issue_2 = [6.2966, 5.5467, 4.5047, 5.3295, 5.1526]
range_issuance_size_2 = [2] * len(x_values)
range_prove_2 = [204.30, 312.06, 300.33, 427.46, 442.36]
range_proof_size_2 = [3624, 5032, 5736, 7144, 7848]
range_verify_2 = [266.10, 351.95, 399.23, 543.84, 495.06]

range_issue_3 = [5.4669, 6.6891, 5.4412, 6.6710, 5.8199]
range_issuance_size_3 = [3] * len(x_values)
range_prove_3 = [140.36, 163.83, 212.08, 249.20, 255.13]
range_proof_size_3 = [2920, 3624, 4328, 5032, 5736]
range_verify_3 = [177.01, 189.19, 260.20, 276.96, 318.17]

range_issue_4 = [7.8510, 7.9311, 7.1706, 7.5528, 7.1238]
range_issuance_size_4 = [4] * len(x_values)
range_prove_4 = [89.589, 110.68, 146.57, 181.12, 170.60]
range_proof_size_4 = [2216, 2920, 3624, 4328, 4328]
range_verify_4 = [116.76, 148.01, 186.73, 230.91, 232.99]

# plot
fig, axs = plt.subplots(1, 3)

# signatures issuance
axs[0].set_title("Issue signatures for set/range elements")
axs[0].set_xlabel("Size of the set/range")
axs[0].set_ylabel("Computational cost [ms] (log scale)")
axs[0].grid(True, which="both", axis="both")

axs[0].set_yscale("log", base=10)

axs[0].plot(x_values, none_issue, label="No proof")
axs[0].plot(x_values, set_issue, label="Set membership proof")
axs[0].plot(x_values, range_issue_2, label="Range proof, u = 2")
axs[0].plot(x_values, range_issue_3, label="Range proof, u = 3")
axs[0].plot(x_values, range_issue_4, label="Range proof, u = 4")

# proof
axs[1].set_title("Prove crendential")
axs[1].set_xlabel("Size of the set/range")
axs[1].set_ylabel("Computational cost [ms]")
axs[1].tick_params(axis="both", which="major", labelsize=12)
axs[1].grid(True, which="both", axis="both")
axs[1].set_ylim(0,600)

axs[1].plot(x_values, none_prove, label="No proof")
axs[1].plot(x_values, set_prove, label="Set membership proof")
axs[1].plot(x_values, range_prove_2, label="Range proof, u = 2")
axs[1].plot(x_values, range_prove_3, label="Range proof, u = 3")
axs[1].plot(x_values, range_prove_4, label="Range proof, u = 4")

# verification
axs[2].set_title("Verify crendential")
axs[2].set_xlabel("Size of the set/range")
axs[2].set_ylabel("Computational cost [ms]")
axs[2].tick_params(axis="both", which="major", labelsize=12)
axs[2].grid(True, which="both", axis="both")
axs[2].set_ylim(0,600)

axs[2].plot(x_values, none_verify, label="No proof")
axs[2].plot(x_values, set_verify, label="Set membership proof")
axs[2].plot(x_values, range_verify_2, label="Range proof, u = 2")
axs[2].plot(x_values, range_verify_3, label="Range proof, u = 3")
axs[2].plot(x_values, range_verify_4, label="Range proof, u = 4")

plt.show()
