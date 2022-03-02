import matplotlib as mpl
import matplotlib.pyplot as plt

mpl.use("GTK4Cairo")

# plt.rc("text", usetext=True)
# plt.rc("text.latex", preamble=r"\usepackage{amsmath}")

# coconut: 10 validators, 7 threshold, 1 private attribute, 0 public attributes
x_values = [10, 50, 100, 500, 1000]

# no proof
none_prove = [12.953] * len(x_values)
none_proof_size = [296] * len(x_values)
none_verify =[21.274] * len(x_values)

# set membership proof
set_issue = [11.103, 68.859, 143.02, 636.25, 1397.3]
set_issuance_size = [value * 96 for value in x_values]
set_prove = [15.253, 17.297, 15.945, 16.809, 16.719]
set_proof_size = [680] * len(x_values)
set_verify = [19.973, 19.297, 18.595, 21.271, 18.511]

range_issue_2 = [2.6061, 2.8156, 2.8066, 2.8068, 2.8043]
range_issuance_size_2 = [2*96] * len(x_values)
range_prove_2 = [108.11, 157.54, 180.87, 227.31, 250.26]
range_proof_size_2 = [3624, 5032, 5736, 7144, 7848]
range_verify_2 = [142.66, 199.98, 227.50, 285.08, 315.72]

range_issue_3 = [4.0110, 4.2114, 4.1863, 3.8844, 4.0984]
range_issuance_size_3 = [3*96] * len(x_values)
range_prove_3 = [86.964, 108.81, 129.64, 142.15, 176.68]
range_proof_size_3 = [2920, 3624, 4328, 5032, 5736]
range_verify_3 = [112.78, 137.6, 166.43, 195.46, 220.69]

range_issue_4 = [5.4523, 5.4427, 5.5236, 5.4560, 5.4542]
range_issuance_size_4 = [4*96] * len(x_values)
range_prove_4 = [61.827, 77.258, 107.91, 130.32, 130.26]
range_proof_size_4 = [2216, 2920, 3624, 4328, 4328]
range_verify_4 = [81.332, 92.245, 137.55, 165.98, 164.94]

# plot
fig, ax1 = plt.subplots()

ax1.set_title("Signatures issuance, service provider-side", fontsize=16)
ax1.set_xlabel("Size of the range", fontsize=14)
ax1.set_ylabel("Computational cost [ms]", fontsize=14)

ax1.plot(x_values, range_issue_2, label="Range proof, base 2", marker="o", alpha=0.8)
ax1.plot(x_values, range_issue_3, label="Range proof, base 3", marker="o", alpha=0.8)
ax1.plot(x_values, range_issue_4, label="Range proof, base 4", marker="o", alpha=0.8)

ax1.legend(loc="upper left", fontsize=12)

ax1.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax1.set_xticks(x_values)
ax1.grid(True, which="both", axis="both", linestyle="dotted")
ax1.set_ylim(0,10)

plt.savefig("Signatures issuance, service provider-side (range)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax2 = plt.subplots()

ax2.set_title("Signatures issuance, service provider-side", fontsize=16)
ax2.set_xlabel("Size of the set", fontsize=14)
ax2.set_ylabel("Computational cost [ms]", fontsize=14)

ax2.plot(x_values, set_issue, label="Set membership proof", marker="o", alpha=0.8, color="red")

ax2.legend(loc="upper left", fontsize=12)

ax2.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax2.set_xticks(x_values)
ax2.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Signatures issuance, service provider-side (set)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax3 = plt.subplots()

ax3.set_title("Signatures issuance, from service provider to user", fontsize=16)
ax3.set_xlabel("Size of the range", fontsize=14)
ax3.set_ylabel("Communication cost [bytes]", fontsize=14)

ax3.plot(x_values, range_issuance_size_2, label="Range proof, base 2", marker="o", alpha=0.8)
ax3.plot(x_values, range_issuance_size_3, label="Range proof, base 3", marker="o", alpha=0.8)
ax3.plot(x_values, range_issuance_size_4, label="Range proof, base 4", marker="o", alpha=0.8)

ax3.legend(loc="upper left", fontsize=12)

ax3.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax3.set_xticks(x_values)
ax3.grid(True, which="both", axis="both", linestyle="dotted")
ax3.set_ylim(0,600)

plt.savefig("Signatures issuance, from service provider to user (range)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax4 = plt.subplots()

ax4.set_title("Signatures issuance, from service provider to user", fontsize=16)
ax4.set_xlabel("Size of the set", fontsize=14)
ax4.set_ylabel("Communication cost [bytes]", fontsize=14)

ax4.plot(x_values, set_issuance_size, label="Set membership proof", marker="o", alpha=0.8, color="red")

ax4.legend(loc="upper left", fontsize=12)

ax4.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax4.set_xticks(x_values)
ax4.grid(True, which="both", axis="both", linestyle="dotted")

plt.savefig("Signatures issuance, from service provider to user (set)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax5 = plt.subplots()

ax5.set_title("Credential preparation, user-side", fontsize=16)
ax5.set_xlabel("Size of the range", fontsize=14)
ax5.set_ylabel("Computational cost [ms]", fontsize=14)

ax5.plot(x_values, range_prove_2, label="Range proof, base 2", marker="o", alpha=0.8)
ax5.plot(x_values, range_prove_3, label="Range proof, base 3", marker="o", alpha=0.8)
ax5.plot(x_values, range_prove_4, label="Range proof, base 4", marker="o", alpha=0.8)
ax5.plot(x_values, none_prove, label="No proof", marker="o", alpha=0.8, color="purple")

ax5.legend(loc="upper left", fontsize=12)

ax5.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax5.set_xticks(x_values)
ax5.grid(True, which="both", axis="both", linestyle="dotted")
ax5.set_ylim(0, 300)

plt.savefig("Credential preparation, user-side (range)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax6 = plt.subplots()

ax6.set_title("Credential preparation, user-side", fontsize=16)
ax6.set_xlabel("Size of the set", fontsize=14)
ax6.set_ylabel("Computational cost [ms]", fontsize=14)

ax6.plot(x_values, set_prove, label="Set membership proof", marker="o", alpha=0.8, color="red")
ax6.plot(x_values, none_prove, label="No proof", marker="o", alpha=0.8, color="purple")

ax6.legend(loc="upper left", fontsize=12)

ax6.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax6.set_xticks(x_values)
ax6.grid(True, which="both", axis="both", linestyle="dotted")
ax6.set_ylim(0,25)

plt.savefig("Credential preparation, user-side (set)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax7 = plt.subplots()

ax7.set_title("Credential preparation, from user to verifier", fontsize=16)
ax7.set_xlabel("Size of the range", fontsize=14)
ax7.set_ylabel("Communication cost [bytes]", fontsize=14)

ax7.plot(x_values, range_proof_size_2, label="Range proof, base 2", marker="o", alpha=0.8)
ax7.plot(x_values, range_proof_size_3, label="Range proof, base 3", marker="o", alpha=0.8)
ax7.plot(x_values, range_proof_size_4, label="Range proof, base 4", marker="o", alpha=0.8)
ax7.plot(x_values, none_proof_size, label="No proof", marker="o", alpha=0.8, color="purple")

ax7.legend(loc="upper left", fontsize=12)

ax7.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax7.set_xticks(x_values)
ax7.grid(True, which="both", axis="both", linestyle="dotted")
ax7.set_ylim(0,10000)

plt.savefig("Credential preparation, from user to verifier (range)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax8 = plt.subplots()

ax8.set_title("Credential preparation, from user to verifier", fontsize=16)
ax8.set_xlabel("Size of the set", fontsize=14)
ax8.set_ylabel("Communication cost [bytes]", fontsize=14)

ax8.plot(x_values, set_proof_size, label="Set membership proof", marker="o", alpha=0.8, color="red")
ax8.plot(x_values, none_proof_size, label="No proof", marker="o", alpha=0.8, color="purple")

ax8.legend(loc="upper left", fontsize=12)

ax8.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax8.set_xticks(x_values)
ax8.grid(True, which="both", axis="both", linestyle="dotted")
ax8.set_ylim(0,900)

plt.savefig("Credential preparation, from user to verifier (set)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax9 = plt.subplots()

ax9.set_title("Credential verification, verifier-side", fontsize=16)
ax9.set_xlabel("Size of the range", fontsize=14)
ax9.set_ylabel("Computational cost [ms]", fontsize=14)

ax9.plot(x_values, range_verify_2, label="Range proof, base 2", marker="o", alpha=0.8)
ax9.plot(x_values, range_verify_3, label="Range proof, base 3", marker="o", alpha=0.8)
ax9.plot(x_values, range_verify_4, label="Range proof, base 4", marker="o", alpha=0.8)
ax9.plot(x_values, none_verify, label="No proof", marker="o", alpha=0.8, color="purple")

ax9.legend(loc="upper left", fontsize=12)

ax9.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax9.set_xticks(x_values)
ax9.grid(True, which="both", axis="both", linestyle="dotted")
ax9.set_ylim(0,400)

plt.savefig("Credential verification, verifier-side (range)", bbox_inches="tight", dpi=300)
# plt.show()

# plot
fig, ax10 = plt.subplots()

ax10.set_title("Credential verification, verifier-side", fontsize=16)
ax10.set_xlabel("Size of the set", fontsize=14)
ax10.set_ylabel("Computational cost [ms]", fontsize=14)

ax10.plot(x_values, set_verify, label="Set membership proof", marker="o", alpha=0.8, color="red")
ax10.plot(x_values, none_verify, label="No proof", marker="o", alpha=0.8, color="purple")

ax10.legend(loc="upper left", fontsize=12)

ax10.tick_params(axis="both", which="major", labelsize=12)
plt.xticks(rotation=90)
ax10.set_xticks(x_values)
ax10.grid(True, which="both", axis="both", linestyle="dotted")
ax10.set_ylim(0,30)

plt.savefig("Credential verification, verifier-side (set)", bbox_inches="tight", dpi=300)
# plt.show()
