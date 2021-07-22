# Author: Jared Crouse
# Organization: Colorado State University
# Creation Date: 4-05-2021
# Last Updated: 5-11-2021
#
# Description:
# This script was created to read the Juliet dataset manifest.xml file after is has 
# been updated with the manifest_update.py script. It reads the support files and 
# files from each test case and runs either FlawFinder of Cppcheck over the files.
# The output is written to a directory called /tool_output_files and the metrics and 
# plots are written to a directory called /metrics_plots.
#
# Usage: 
#	On Mac or Linux: (this example will run cppcheck)
#		python3 sa_from_manifest.py <full_path_to_manifest_file> -t cpp
#
#	With verbose option: (outputs information to terminal)
#		python3 sa_from_manifest.py <full_path_to_manifest_file> -t flw -v
#
#	With cwe option: (this example will only run cwes 78, 511 & 780)
#		python3 sa_from_manifest.py <full_path_to_manifest_file> -t cpp -c 78,511,780
#
#	With flow variant option: (this example will run flow variants 15 through 18)
#		python3 sa_from_manifest.py <full_path_to_manifest_file> -t flw -f 15,16,17,18
#
# Note: Without specifying the verbose option the default is 
#		false and no output will show up in the terminal. Also, the
#		default cwe option is to run all cwes except 506 & 510. The default 
#		flow variant argument is all.
#


import os
import sys
import argparse
import pickle
import matplotlib.pyplot as plt
import pandas as pd
from Manifest import Manifest
from config import read_cpp_conf, read_flw_conf
from run_log import process_testcase
from sa_utils import formt, calc_metrics, make_result_dir


def main():
	'''
	This is the main function of the script, it parses any arguments, scans all files
	in the test directory, creates a dictionary of variables and checks for false
	positive causing flow variants. See other methods for more details.
	'''
	man_path, flag_list, cwe_list, fv_list = parser()
	result_dir = make_result_dir(man_path, flag_list[0])

	# Format: {'CWE': [TP, FN, FP, TN]}
	cwe_metrics = {}
	for cwe in cwe_list:
		cwe_metrics[cwe] = [0, 0, 0, 0]
	# Format: {'FV': [TP, FN, FP, TN]}
	fv_metrics = {}
	for fv in fv_list:
		fv_metrics[fv] = [0, 0, 0, 0]
	# Format: [TP, FN, FP, TN]
	tool_metrics = [0, 0, 0, 0]
	man = Manifest(man_path)

	fp_log = []
	tp_log = []
	testcases_processed = 0

	try:
		os.mkdir(result_dir + '/tool_output_files')
	except OSError as error:
		print(error)
		sys.exit()

	while True:
		out_f, f_list = man.get_next()

		if out_f == 'STOP':
			if flag_list[0]:
				print('- End of manifest file reached')
			break

		out_f_parts = out_f.split('_')
		if out_f_parts[0] in cwe_list and out_f_parts[1] in fv_list:
			if flag_list[0]:
				print('- Processing : ' + out_f)
					
			TP = 0
			FN = 0
			FP = 0
			TN = 0
			cmd = []

			if flag_list[1]: #CPP
				# Make output file name
				scan_output = result_dir + '/tool_output_files/' + out_f + '.xml'
				# Create terminal command from config & f_list
				cmd.append(read_cpp_conf(f_list))
			elif flag_list[2]: #FLW
				# Make output file name
				scan_output = result_dir + '/tool_output_files/' + out_f_parts[0] + '_' + out_f_parts[1] + '_' + out_f_parts[2] + '.html'
				# Create terminal command from config & f_list
				cmd.append(read_flw_conf(f_list))
			else:
				print('Something went wrong with tool selection!')
				sys.exit()

			# Skip test cases where files are missing
			if 'NULL' not in f_list:
				testcases_processed += 1
				# Scan source files (not support) for ranges of good & bad functions
				TP, FN, FP, TN = process_testcase(f_list[5:], cmd[0], fp_log, tp_log, flag_list, scan_output, (int(out_f_parts[0]), int(out_f_parts[1])))
				if TP == 0 and FN == 0 and FP == 0 and TN == 0:
					testcases_processed -= 1
					if flag_list[0]:
						print('- TP FN FP TN all equal zero')
			else:
				testcases_processed -= 1
				#if flag_list[0]:
				print('- Files missing for this testcase, skipping!')

			# Update CWE, FV and tool counts
			cwe_metrics[out_f_parts[0]][0] += TP
			fv_metrics[out_f_parts[1]][0] += TP
			tool_metrics[0] += TP
			cwe_metrics[out_f_parts[0]][1] += FN
			fv_metrics[out_f_parts[1]][1] += FN
			tool_metrics[1] += FN
			cwe_metrics[out_f_parts[0]][2] += FP
			fv_metrics[out_f_parts[1]][2] += FP
			tool_metrics[2] += FP
			cwe_metrics[out_f_parts[0]][3] += TN
			fv_metrics[out_f_parts[1]][3] += TN
			tool_metrics[3] += TN

	#if flag_list[0]:
	print('- Testcases processed: ', testcases_processed)
	print('- Testcases in full dataset: 63,871 (excluding CWE 506 & 510)') # 64,099 - 228 (for CWE 506 & 510)

	# Write FP dict
	fp_file = result_dir + '/fp_dict.pkl'
	with open(fp_file, 'wb') as fp_out:
		pickle.dump(fp_log, fp_out)
		if flag_list[0]:
			print('- File created : ' + fp_file)

	# Write TP dict
	tp_file = result_dir + '/tp_dict.pkl'
	with open(tp_file, 'wb') as tp_out:
		pickle.dump(tp_log, tp_out)
		if flag_list[0]:
			print('- File created : ' + tp_file)

	plot_log(result_dir, flag_list, cwe_metrics, fv_metrics, tool_metrics)


def plot_log(result_dir, flag_list, cwe_metrics, fv_metrics, tool_metrics):
	'''
	This fucntion uses metrics dictionaries to calculate accuracy, recall & prob false alarm
	to generate plots and write information to a file for later analysis.
	'''
	metrics_out = pd.DataFrame(columns = ['Name', 'Accuracy', 'Recall', 'Prob. of False Alarm'])

	if flag_list[0]:
		print('\n Calculating metrics...\n')
	try:
		os.mkdir(result_dir + '/metrics_plots')
	except OSError as error:
		print(error)

	# For tool overall
	tool_acc, tool_rec, tool_prob = calc_metrics(tool_metrics)
	if flag_list[1]: #CPP
		metrics_out.loc[len(metrics_out.index)] = ['Cppcheck', formt(tool_acc), formt(tool_rec), formt(tool_prob)]
	else:
		metrics_out.loc[len(metrics_out.index)] = ['FlawFinder', formt(tool_acc), formt(tool_rec), formt(tool_prob)]

	if flag_list[0]:
		print('Overall for tool:')
		print('Accuracy: ', formt(tool_acc), end = '')
		print('%')
		print('Recall: ', formt(tool_rec), end = '')
		print('%')
		print('Probability of false alarm: ', formt(tool_prob), end = '')
		print('%\n')

	fig = plt.figure()
	ax = fig.add_subplot()
	ax.set_ylim([0, 100])
	metrx = ['Accuracy', 'Recall', 'Prob. False Alarm']
	metrx_vals = [tool_acc, tool_rec, tool_prob]
	ax.bar(metrx, metrx_vals, color=['tab:green', 'tab:blue', 'tab:red'])
	ax.set_ylabel('Percentage')
	if flag_list[1]: #CPP
		ax.set_title('Overall Cppcheck Metrics')
	else:
		ax.set_title('Overall FlawFinder Metrics')
	for i, v in enumerate(metrx_vals):
		plt.text(i, v, formt(v), color='black', va='center', ha='center')
	plt.savefig(result_dir + '/metrics_plots/tool_metrics.png', dpi=300, format='png')
	plt.close()

	# For each CWE
	for cwe in cwe_metrics.keys():
		cwe_acc, cwe_rec, cwe_prob = calc_metrics(cwe_metrics[cwe])
		metrics_out.loc[len(metrics_out.index)] = ['CWE' + cwe, formt(cwe_acc), formt(cwe_rec), formt(cwe_prob)]

		if flag_list[0]:
			print('For each CWE:')
			print('CWE: ', cwe)
			print('\tAccuracy: ', formt(cwe_acc), end = '')
			print('%')
			print('\tRecall: ', formt(cwe_rec), end = '')
			print('%')
			print('\tProbability of false alarm: ', formt(cwe_prob), end = '')
			print('%')

		fig = plt.figure()
		ax = fig.add_subplot()
		ax.set_ylim([0, 100])
		metrx = ['Accuracy', 'Recall', 'Prob. False Alarm']
		metrx_vals = [cwe_acc, cwe_rec, cwe_prob]
		ax.bar(metrx, metrx_vals, color=['tab:green', 'tab:blue', 'tab:red'])
		ax.set_ylabel('Percentage')
		if flag_list[1]: #CPP
			ax.set_title('CWE-' + cwe + ' Metrics (Cppcheck)')
		else:
			ax.set_title('CWE-' + cwe + ' Metrics (FlawFinder)')
		for i, v in enumerate(metrx_vals):
			plt.text(i, v, formt(v), color='black', va='center', ha='center')
		plt.savefig(result_dir + '/metrics_plots/cwe' + cwe + '_metrics.png', dpi=300, format='png')
		plt.close()

	# For each flow variant
	for fv in fv_metrics.keys():
		fv_acc, fv_rec, fv_prob = calc_metrics(fv_metrics[fv])
		metrics_out.loc[len(metrics_out.index)] = ['FV' + fv, formt(fv_acc), formt(fv_rec), formt(fv_prob)]

		if flag_list[0]:
			print('\nFor each flow variant:')	
			print('Flow variant: ', fv)
			print('\tAccuracy: ', formt(fv_acc), end = '')
			print('%')
			print('\tRecall: ', formt(fv_rec), end = '')
			print('%')
			print('\tProbability of false alarm: ', formt(fv_prob), end = '')
			print('%')

		fig = plt.figure()
		ax = fig.add_subplot()
		ax.set_ylim([0, 100])
		metrx = ['Accuracy', 'Recall', 'Prob. False Alarm']
		metrx_vals = [fv_acc, fv_rec, fv_prob]
		ax.bar(metrx, metrx_vals, color=['tab:green', 'tab:blue', 'tab:red'])
		ax.set_ylabel('Percentage')
		if flag_list[1]: #CPP
			ax.set_title('Flow Variant ' + fv + ' Metrics (Cppcheck)')
		else:
			ax.set_title('Flow Variant ' + fv + ' Metrics (FlawFinder)')
		for i, v in enumerate(metrx_vals):
			plt.text(i, v, formt(v), color='black', va='center', ha='center')
		plt.savefig(result_dir + '/metrics_plots/fv' + fv + '_metrics.png', dpi=300, format='png')
		plt.close()

	# Write dataframe
	metrics_out.to_csv(result_dir + '/metrics_plots/all_results.csv', index=False, encoding='utf-8')


def parser():
	'''
	This function parses the arguments passed by the user, ensures the manifest 
	file exists for the test dataset and returns the relevant information.
	'''
	# Includes 116 of 118 CWEs, 506 & 510 excluded
	cwes = ('015,023,036,078,090,114,121,122,123,124,126,127,134,176,188,190,191,194,195,196,197,'
			'222,223,226,242,244,247,252,253,256,259,272,273,284,319,321,325,327,328,338,364,'
			'366,367,369,377,390,391,396,397,398,400,401,404,415,416,426,427,440,457,459,464,'
			'467,468,469,475,476,478,479,480,481,482,483,484,500,511,526,534,535,546,561,562,'
			'563,570,571,587,588,590,591,605,606,615,617,620,665,666,667,672,674,675,676,680,'
			'681,685,688,690,758,761,762,773,775,780,785,789,832,835,843')

	# Includes all 48 flow variants
	fvs = ('01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,16,17,18,21,22,31,32,33,34,41,42,43,44,'
		'45,51,52,53,54,61,62,63,64,65,66,67,68,72,73,74,81,82,83,84')

	parser = argparse.ArgumentParser(description='Run cppcheck, flawfinder on testcases from manifest.xml')
	parser.add_argument('Path', metavar='path', type=str, help='Path to manifest file')
	parser.add_argument('-t', '--tool', type=str, required=True, help='Tool flag')
	parser.add_argument('-v', '--verbose', required=False, default=False, help='Verbose flag', action='store_true')
	parser.add_argument('-c', '--cwe', required=False, default=cwes, help='CWE flag')
	parser.add_argument('-f', '--fv', required=False, default=fvs, help='Flow variant flag')

	args = parser.parse_args()
	input_path = args.Path
	tool = args.tool
	verbose = args.verbose
	cwe = args.cwe
	fv = args.fv

	if not os.path.isfile(input_path):
	    print('The manifest specified does not exist!')
	    sys.exit()

	cpp_flag = False
	flw_flag = False
	if 'cpp' == tool:
		cpp_flag = True
	elif 'flw' in tool:
		flw_flag = True
	else:
		print('Only one tool can be used at a time, specify either \"cpp\" or \"flw\"')
		sys.exit()

	cwe_list = cwe.split(',')
	fv_list = fv.split(',')

	flag_list = [verbose, cpp_flag, flw_flag]

	if verbose:
		print('Starting benchmarking...')

	return input_path, flag_list, cwe_list, fv_list


if __name__ == "__main__":
	main()
