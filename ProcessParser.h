#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"


using namespace std;

class ProcessParser{
private:
    std::ifstream stream;
public:
    static string getCmd(string pid);
    static vector<string> getPidList();
    static std::string getVmSize(string pid);
    static std::string getCpuPercent(string pid);
    static long int getSysUpTime();
    static std::string getProcUpTime(string pid);
    static string getProcUser(string pid);
    static vector<string> getSysCpuPercent(string coreNumber = "");
    static float getSysRamPercent();
    static string getSysKernelVersion();
    static int getTotalThreads();
    static int getTotalNumberOfProcesses();
    static int getNumberOfRunningProcesses();
    static string getOSName();
    static std::string printCpuStats(std::vector<std::string> values1, std::vector<std::string>values2);
    static bool isPidExisting(string pid);

    /* CPU INFO */
    static int getNumberOfCores();
    static float getSysActiveCpuTime(vector<string> values);
    static float getSysIdleCpuTime(vector<string>values);
};

string ProcessParser::getCmd(string pid) {
    string path = Path::basePath() + pid + Path::cmdPath();
    string line;

    ifstream file;
    Util::getStream(path, file);

    getline(file, line);

    return line;
}

vector<string> ProcessParser::getPidList() {
    DIR* dir;

    vector<string> pids;

    if(!(dir = opendir(Path::basePath().c_str()))) {
        throw std::runtime_error(std::strerror(errno));
    }

    while(dirent* dirEntry = readdir(dir)) {
        /* check if this entry is a directory */
        if(dirEntry->d_type != DT_DIR) {
            continue;
        }
        /* check that all characters are digits to represent a valid PID */
        if(all_of(dirEntry->d_name, dirEntry->d_name + strlen(dirEntry->d_name), [](char c){
            return isdigit(c);
        })) {
            pids.push_back(dirEntry->d_name);
        }
    }

    if(closedir(dir)) {
        throw std::runtime_error(std::strerror(errno));
    }
    return pids;
}

string ProcessParser::getVmSize(string pid) {
    string path = Path::basePath() + pid + Path::statusPath();
    string line;
    string searchItem = "VmData";
    /* return 0 in the rare occurence we don't find VmData in the file */
    float result = 0;

    ifstream file;
    Util::getStream(path, file);

    while(getline(file, line)) {
        if(line.compare(0, searchItem.length(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);

            /* index 1 contains size of used RAM in KB
                convert to GB */
            result = (stof(tokens[1])/float(1024));
            break;
        }
    }
    return to_string(result);
}

string ProcessParser::getCpuPercent(string pid) {
    string path = Path::basePath() + pid + "/" + Path::statPath();
    string line;
    float result;
    ifstream file;
    Util::getStream(path, file);

    getline(file, line);

    istringstream strBuff(line);
    istream_iterator<string> begin(strBuff);
    istream_iterator<string> end;

    vector<string> tokens(begin, end);

    float utime = stof(ProcessParser::getProcUpTime(pid));
    float stime = stof(tokens[14]);
    float cutime = stof(tokens[15]);
    float cstime = stof(tokens[16]);
    float starttime = stof(tokens[21]);
    float uptime = ProcessParser::getSysUpTime();
    float freq = sysconf(_SC_CLK_TCK);
    float total_time = utime + stime + cutime + cstime;
    float seconds = uptime - (starttime/freq);
    result = 100.0*((total_time/freq)/seconds);
    return to_string(result);
}

long int ProcessParser::getSysUpTime() {
    string path = Path::basePath() + Path::upTimePath();
    string line;
    ifstream file;
    Util::getStream(path, file);

    getline(file, line);

    istringstream strBuff(line);
    istream_iterator<string> begin(strBuff);
    istream_iterator<string> end;

    vector<string> tokens(begin, end);
    return stoi(tokens[0]);
}

string ProcessParser::getProcUpTime(string pid) {

    string path = Path::basePath() + pid + "/" + Path::statPath();
    string line;
    ifstream file;
    Util::getStream(path, file);

    getline(file, line);

    istringstream strBuff(line);
    istream_iterator<string> begin(strBuff);
    istream_iterator<string> end;

    vector<string> tokens(begin, end);

    return to_string(float(stof(tokens[13])/sysconf(_SC_CLK_TCK)));
}

string ProcessParser::getProcUser(string pid) {

    string path = Path::basePath() + pid + Path::statusPath();
    string line;
    string searchItem = "Uid:";
    ifstream file;
    Util::getStream(path, file);

    string uid;
    bool foundUID = false;

    while(getline(file, line)) {
        if(line.compare(0, searchItem.length(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);

            uid = tokens[1];
            foundUID = true;
            break;
        }
    }

    if(!foundUID) {
        return "";
    }

    Util::getStream("/etc/passwd", file);
    while (getline(file, line)) {
        if (line.find("x:" + uid) != std::string::npos) {
            return line.substr(0, line.find(":"));
        }
    }
    return "";
}

vector<string> ProcessParser::getSysCpuPercent(string coreNumber) {
    string path = Path::basePath() + Path::statPath();
    string line;
    ifstream file;
    string searchItem = "cpu" + coreNumber;
    Util::getStream(path, file);

    while (std::getline(file, line)) {
        if (line.compare(0, searchItem.size(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            return tokens;
        }
    }
    return (vector<string>());
}

float ProcessParser::getSysRamPercent() {
    string path = Path::basePath() + Path::memInfoPath();
    string line;
    ifstream file;
    string searchItem1 = "MemAvailable:";
    string searchItem2 = "MemFree:";
    string searchItem3 = "Buffers:";
    Util::getStream(path, file);

    float totalMem = 0;
    float freeMem = 0;
    float buffers = 0;

    while (std::getline(file, line)) {
        if (line.compare(0, searchItem1.size(), searchItem1) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            totalMem = stof(tokens[1]);
        }
        if (line.compare(0, searchItem2.size(), searchItem2) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            freeMem = stof(tokens[1]);
        }
        if (line.compare(0, searchItem3.size(), searchItem3) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            buffers = stof(tokens[1]);
        }
    }
    return float(100.0*( 1- ( freeMem / ( totalMem - buffers ))));
}

string ProcessParser::getSysKernelVersion() {
    string path = Path::basePath() + Path::versionPath();
    string line;
    ifstream file;
    string searchItem = "Linux version ";
    Util::getStream(path, file);
    while (std::getline(file, line)) {
        if (line.compare(0, searchItem.size(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            return tokens[2];
        }
    }
    return "";
}

int ProcessParser::getTotalNumberOfProcesses() {
    int total = 0;
    string path = Path::basePath() + Path::statPath();
    string line;
    ifstream file;
    string searchItem = "processes";
    Util::getStream(path, file);
    while (std::getline(file, line)) {
        if (line.compare(0, searchItem.size(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            total += stoi(tokens[1]);
            break;
        }
    }
    return total;
}

int ProcessParser::getTotalThreads() {
    int total = 0;
    string line;
    ifstream file;
    string searchItem = "Threads:";

    vector<string> pidList = ProcessParser::getPidList();

    for(auto pid : pidList) {
        string path = Path::basePath() + pid + "/" + Path::statPath();
        Util::getStream(path, file);
        while (std::getline(file, line)) {
            if (line.compare(0, searchItem.size(), searchItem) == 0) {
                istringstream strBuff(line);
                istream_iterator<string> begin(strBuff);
                istream_iterator<string> end;

                vector<string> tokens(begin, end);
                total += stoi(tokens[1]);
                break;
            }
        }
    }
    
    return total;
}

int ProcessParser::getNumberOfRunningProcesses() {
    int total = 0;
    string path = Path::basePath() + Path::statPath();
    string line;
    ifstream file;
    string searchItem = "procs_running";
    Util::getStream(path, file);
    while (std::getline(file, line)) {
        if (line.compare(0, searchItem.size(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            total += stoi(tokens[1]);
            break;
        }
    }
    return total;
}

string ProcessParser::getOSName() {
    string path = Path::osNamePath();
    string line;
    ifstream file;
    string searchItem = "PRETTY_NAME=";
    Util::getStream(path, file);
    while (std::getline(file, line)) {
        if (line.compare(0, searchItem.size(), searchItem) == 0) {
            std::size_t found = line.find("=");
            found++;
            string result = line.substr(found);
            result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
            return result;
        }
    }
    return "";
}

string ProcessParser::printCpuStats(vector<string> values1, vector<string> values2) {
    float active_time = getSysActiveCpuTime(values2) - getSysActiveCpuTime(values1);
    float idle_time = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float total_time = active_time + idle_time;
    float result = 100.0*(active_time / total_time);
    return to_string(result);
}


/* CPU INFO */
int ProcessParser::getNumberOfCores()
{
    /* get number of host cpu cores */
    string path = Path::basePath() + Path::cpuInfoPath();
    string line;
    ifstream file;
    string searchItem = "cpu cores";
    Util::getStream(path, file);
    while (std::getline(file, line)) {
        if (line.compare(0, searchItem.size(), searchItem) == 0) {
            istringstream strBuff(line);
            istream_iterator<string> begin(strBuff);
            istream_iterator<string> end;

            vector<string> tokens(begin, end);
            return stoi(tokens[3]);
        }
    }
    return 0;
}

float ProcessParser::getSysActiveCpuTime(vector<string> values) {
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float ProcessParser::getSysIdleCpuTime(vector<string>values) {
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}


bool ProcessParser::isPidExisting(string pid) {
    vector<string> pidList = ProcessParser::getPidList();

    /* Iterator used to store the position  
     of searched element */
    std::vector<string>::iterator it;

    it = std::find(pidList.begin(), pidList.end(), pid); 
    if (it != pidList.end()) 
    { 
       return true;
    } 
    return false;
}



