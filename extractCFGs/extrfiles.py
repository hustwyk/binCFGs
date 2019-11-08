import os
import pdb
import sys
from optparse import OptionParser
from binCFGStruct import CFG_Bin_Custom, CFG_Func_Custom, CFG_Node_Custom, FuncMapping, Resol_objdump, Bin_CFG_Graph

def optionParse():
    parser = OptionParser()
    parser.add_option('-f', '--file', dest='filename', help='Specify the file to extract the CFG.', metavar='FILE')
    parser.add_option('-c', '--clanguage', action='store_true', dest='clanguage', default=False, help='Change the default language \
                        from assembly to c-language')
    parser.add_option('-s', '--save', action='store_true', dest='save', default=False, help='Save the CFG info a yaml file, \
                        default file name is ${BIN_NAME}.yaml, default path is current path. -o can change output \
                        path and file name, and -O can change output directory.')
    parser.add_option('-o', '--output', dest='output', help='Specify the output yaml file name and saving path. \
                        When using -o, -s can be omitted.')
    parser.add_option('-O', '--outputdirectory', dest='outputdirectory', help='Specify the output yaml file saving \
                        path, yaml file name will be ${BIN_NAME}.yaml. When using -O, -s can be omitted.')
    parser.add_option('-d', '--directory', dest='directory', help='Choose the target directory containing the target \
                        binary files.')
    parser.add_option('-q', '--quiet', action='store_false', dest='quiet', default=True, help='Make the script running silently.')
    (options, args) = parser.parse_args()
    if (options.filename and options.directory):
        print('Error: You can only specify -f or -d, not both.')
        sys.exit()
    if (options.output and options.outputdirectory):
        print('Error: You can only specify -o or -O, not both.')
        sys.exit()
    if options.filename:
        if not os.path.exists(options.filename):
            print('Error: The specify file is not exists.')
            sys.exit()
        elif not os.path.isfile(options.filename):
                print('Error: The specify object is not a file.')
                sys.exit()
        else:
            binCFGGraph = Bin_CFG_Graph(options.filename)
            fileName = os.path.split(options.filename)[-1]
            outputPath = ''
            saveOp = 0
            if options.output:
                saveOp = 1
                if os.path.exists(options.output):
                    os.remove(options.output)
                else:
                    yamlName = os.path.split(options.output)[-1]
                    yamlPath = os.path.split(options.output)[0]
                    if not os.path.exists(yamlPath):
                        os.makedirs(yamlPath)
                outputPath = options.output
            elif options.outputdirectory:
                saveOp = 1
                if os.path.isfile(options.outputdirectory):
                    print('Error: The specify object is not a directory.')
                    sys.exit()
                else:
                    if not os.path.exists(options.outputdirectory):
                        os.makedirs(options.outputdirectory)
                    tmpYamlName = os.path.splitext(fileName)[0] + '.yaml'
                    outputPath = os.path.join(options.outputdirectory, tmpYamlName)
            elif (not options.output) and (not options.outputdirectory) and options.save:
                saveOp = 1
                outputPath = os.path.splitext(fileName)[0] + '.yaml'
            if options.quiet:
                if options.clanguage:
                    dict_func_graph = binCFGGraph.get_graph(1, 0, saveOp, outputPath)
                else:
                    dict_func_graph = binCFGGraph.get_graph(1, 1, saveOp, outputPath)
            else:
                dict_func_graph = binCFGGraph.get_graph(0, 0, saveOp, outputPath)
            sys.exit()
    if options.directory:
        print('Error: This feature is not implemented in this script.')
        pass # TODO:parallel

if __name__ == "__main__":
    optionParse()
