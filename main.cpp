#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <time.h>
#include <cstdlib>
#include <string_view>
#include <array>
#include <iomanip>
#include <algorithm>
#include <iterator>

#include <mysql_connection.h>
#include <mysql_driver.h>

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "base64.hpp"

const int PORT = 12345;
const int MAX_CONNECTIONS = 5;
const int BUFFER_SIZE = 1024;

class Bosses {
    public:
        struct Boss1 {
            const int hp = 150;
            const int defense = 50;
            const int attackDamage = 10;
            const int loot = 30;
        };

        Boss1 boss1;
};

class Weapons {
    public:
        struct WoodenSword {
            const int attackDamage = 10;
        };

        WoodenSword woodenSword;
};

std::vector<std::string> splitRequest(std::string request) {
    std::vector<std::string> vect;
    std::stringstream ss(request);
    std::string s;

    while(std::getline(ss, s, ',')) {
        vect.push_back(s);
    }

    return vect;
}

const std::string getCurrentTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    return buf;
}

std::string generateRandomNumber() {
    srand((unsigned) time(NULL));
    return std::to_string(rand());
}

std::string HMACSHA256(std::string_view key, std::string_view msg) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int hashLength;

    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<unsigned char const*>(msg.data()), static_cast<int>(msg.size()), hash.data(), &hashLength);
    return std::string{reinterpret_cast<char const*>(hash.data()), hashLength};
}

std::string generate_sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    const unsigned char* data = (const unsigned char*)str.c_str();
    SHA256(data, str.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string getInventory(const std::string username) {
    std::vector<std::string> inventory;

    try {
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        sql::PreparedStatement *prep_stmt;

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
        /* Connect to the MySQL test database */
        con->setSchema("user_data");
       
       prep_stmt = con->prepareStatement("SELECT slot1, slot2, slot3, slot4, slot5, slot6, slot7, slot8, slot9, slot10, slot11, slot12, slot13, slot14, slot15, slot16 FROM inventory WHERE username = ?");
       prep_stmt->setString(1, username);

       res = prep_stmt->executeQuery();

       if (res->next()) {
        for (int i = 1; i <= 16; i++) {
            inventory.push_back(res->getString("slot" + std::to_string(i)));
        }
       }
            
        delete prep_stmt;


        delete res;

        delete con;

        } catch (sql::SQLException &e) {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line "
            << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() <<
            " )" << std::endl;
    }

    std::ostringstream oss;

    if (!inventory.empty()) {
        std::copy(inventory.begin(), inventory.end()-1, std::ostream_iterator<std::string>(oss, ","));

        oss << inventory.back();
    }

    return oss.str();
}

void addInventoryItem(std::string username, std::string item) {
    try {
    sql::Driver *driver;
    sql::Connection *con;
    sql::Statement *stmt;
    sql::ResultSet *res;
    sql::PreparedStatement *prep_stmt;

    /* Create a connection */
    driver = get_driver_instance();
    con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
    /* Connect to the MySQL test database */
    

    con->setSchema("user_data");

    prep_stmt = con->prepareStatement("SELECT slot1, slot2, slot3, slot4, slot5, slot6, slot7, slot8, slot9, slot10, slot11, slot12, slot13, slot14, slot15, slot16 FROM inventory WHERE username = ?");
    prep_stmt->setString(1, username);

    res = prep_stmt->executeQuery();

    for (int i = 1; i <= 16; i++) {
        if (res->getString("slot" + std::to_string(i)) != "EMPTY") {
            prep_stmt = con->prepareStatement("INSERT INTO inventory(slot" + std::to_string(i) + ") VALUES (?) WHERE username = ?");
            prep_stmt->setString(1, item);
            prep_stmt->setString(2, username);

            res = prep_stmt->executeQuery();
        }
    }

    
                
                
                
    delete prep_stmt;


    delete res;

    delete con;

    } catch (sql::SQLException &e) {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line "
            << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() <<
            " )" << std::endl;
    }
}

int getGold(std::string username) {
    try {
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        sql::PreparedStatement *prep_stmt;

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
        /* Connect to the MySQL test database */
        con->setSchema("user_data");

        prep_stmt = con->prepareStatement("SELECT gold FROM inventory WHERE username = ?");
        prep_stmt->setString(1, username);
        

        res = prep_stmt->executeQuery();

        if (res->next()) {
            return res->getInt("gold");
        } else {
            std::cout << "Error getting gold" << std::endl;
        }
        delete prep_stmt;


        delete res;

        delete con;

    } catch (sql::SQLException &e) {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line "
            << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() <<
            " )" << std::endl;
    }
    return 0;
}

void addGold(std::string username, int amount) {
    try {
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        sql::PreparedStatement *prep_stmt;

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
        /* Connect to the MySQL test database */
        con->setSchema("user_data");

        prep_stmt = con->prepareStatement("INSERT INTO inventory(gold) VALUES (?) WHERE username = ?");
        prep_stmt->setInt(1, amount);
        prep_stmt->setString(2, username);
        

        res = prep_stmt->executeQuery();

        delete prep_stmt;


        delete res;

        delete con;

    } catch (sql::SQLException &e) {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line "
            << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() <<
            " )" << std::endl;
    }
}

bool checkForInventoryItem(std::string username, std::string item) {
    try {
        sql::Driver *driver;
        sql::Connection *con;
        sql::Statement *stmt;
        sql::ResultSet *res;
        sql::PreparedStatement *prep_stmt;

        /* Create a connection */
        driver = get_driver_instance();
        con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
        /* Connect to the MySQL test database */
        con->setSchema("user_data");
       
       prep_stmt = con->prepareStatement("SELECT slot1, slot2, slot3, slot4, slot5, slot6, slot7, slot8, slot9, slot10, slot11, slot12, slot13, slot14, slot15, slot16 FROM inventory WHERE username = ?");
       prep_stmt->setString(1, username);

       res = prep_stmt->executeQuery();

       if (res->next()) {
        for (int i = 1; i <= 16; i++) {
            if (res->getString("slot" + std::to_string(i)) == item) {
                return true;
            }
        }
        return false;
       }
            
        delete prep_stmt;


        delete res;

        delete con;

        } catch (sql::SQLException &e) {
        std::cout << "# ERR: SQLException in " << __FILE__;
        std::cout << "(" << __FUNCTION__ << ") on line "
            << __LINE__ << std::endl;
        std::cout << "# ERR: " << e.what();
        std::cout << " (MySQL error code: " << e.getErrorCode();
        std::cout << ", SQLState: " << e.getSQLState() <<
            " )" << std::endl;
    }
    return false;
}

int bossFight(int clientSocket, std::string username, std::string bossItem, std::string weapon, std::string healItem) {
    Bosses b;
    Weapons w;

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int bytesReceived;

    int bossHp;
    int bossDefense;
    int bossAttackDamage;
    int bossLoot;

    int weaponAttackDamage;

    int playerHp = 100;
    int playerDefense = 50;

    std::string victoryMessage = "playerWon,";
    std::string looseMessage = "playerLost,";
    std::string errorMessage = "failed,";

    if (bossItem == "boss1") {
        bossHp = b.boss1.hp;
        bossDefense = b.boss1.defense;
        bossAttackDamage = b.boss1.attackDamage;
        bossLoot = b.boss1.loot;
    }

    if (weapon == "wooden_sword" && checkForInventoryItem(username, weapon)) {
        weaponAttackDamage = w.woodenSword.attackDamage;
    }

    while (bossHp > 0 || playerHp > 0 || bossHp > 0 && playerHp > 0) {
        bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        std::string receivedMessage(buffer, bytesReceived);
        std::vector vect = splitRequest(receivedMessage);

        if (vect[0] == "ATTACK") {
            bossHp -= weaponAttackDamage;
            playerHp -= bossAttackDamage;
        } else if (vect[0] == "DEFEND") {
            if (playerDefense > 0) {
                playerDefense -= bossAttackDamage;
            } else {
                playerHp -= bossAttackDamage;
            }
        }
    }

    if (bossHp == 0) {
        send(clientSocket, victoryMessage.c_str(), strlen(victoryMessage.c_str()), 0);
        return bossLoot;
    } else if (playerHp == 0) {
        send(clientSocket, looseMessage.c_str(), strlen(looseMessage.c_str()), 0);
        return 0;
    } else {
        send(clientSocket, errorMessage.c_str(), strlen(errorMessage.c_str()),0);
        return 0;
    }


}

void gameLoop(int clientSocket, std::string username) {
    while (true) {
        if (username == ".failedLogin") {
            break;
        }

        std::cout << getInventory(username) << std::endl;

        break;

        
    }
}


void handleClient(int clientSocket) {
    std::cout << "Client connected" << "\n";
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int bytesReceived;

    //std::string token = getCurrentTime() + generateRandomNumber();

    std::string username;
    std::string password;

    std::string loggedInUsername;

    bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);

    if (bytesReceived > 0) {
        std::string receivedMessage(buffer, bytesReceived);
        memset(buffer, 0, BUFFER_SIZE);
        std::cout << "Received: " << receivedMessage << std::endl;

        std::vector<std::string> vect = splitRequest(receivedMessage);

        if (vect[0] == "LOGIN" && vect.size() >= 3) {
            username = vect[1];
            password = vect[2];

            try {
                sql::Driver *driver;
                sql::Connection *con;
                sql::Statement *stmt;
                sql::ResultSet *res;
                sql::PreparedStatement *prep_stmt;

                /* Create a connection */
                driver = get_driver_instance();
                con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
                /* Connect to the MySQL test database */
                con->setSchema("user_credentials");

                prep_stmt = con->prepareStatement("SELECT password FROM user WHERE username = ?");
                prep_stmt->setString(1, username);
                //prep_stmt->setString(2, password);

                res = prep_stmt->executeQuery();

                if (res->next()) {
                    std::string password = res->getString("password");
                    std::string token = getCurrentTime() + generateRandomNumber();
                    std::string hashedPassword = base64::to_base64(HMACSHA256(token, password));
                    send(clientSocket, token.c_str(), strlen(token.c_str()), 0);
                    bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
                    std::string receivedMessage(buffer, bytesReceived);
                    vect = splitRequest(receivedMessage);
                    if (vect[0] == "PASSWORD" && vect.size() >= 3) {
                        if (vect[1] == hashedPassword) {
                            std::cout << "Login successful!" << std::endl;
                            
                            loggedInUsername = vect[1];

                            gameLoop(clientSocket, loggedInUsername);
                        } else {
                            std::cout << "Login failed. Invalid username or password." << std::endl;
                            std::cout << "Reveived password: " << vect[1] << "," << std::endl;
                            std::cout << "Correct password: " << hashedPassword << "," << std::endl;

                            loggedInUsername = ".failedLogin";
                        }
                    }
                    //std::cout << "Login successful!" << std::endl;
                    //send(clientSocket, "Login successful!", strlen("Login successful!"), 0);
                } else {
                    std::cout << "Login failed. Invalid username or password." << std::endl;
                    send(clientSocket, "Login failed. Invalid username or password.", strlen("Login failed. Invalid username or password."), 0);
                }
                delete prep_stmt;


                delete res;

                delete con;

            } catch (sql::SQLException &e) {
                std::cout << "# ERR: SQLException in " << __FILE__;
                std::cout << "(" << __FUNCTION__ << ") on line "
                    << __LINE__ << std::endl;
                std::cout << "# ERR: " << e.what();
                std::cout << " (MySQL error code: " << e.getErrorCode();
                std::cout << ", SQLState: " << e.getSQLState() <<
                    " )" << std::endl;
            }
        } else if (vect[0] == "REGISTER" && vect.size() >= 3) {
            username = vect[1];
            password = vect[2];

            try {
                sql::Driver *driver;
                sql::Connection *con;
                sql::Statement *stmt;
                sql::ResultSet *res;
                sql::PreparedStatement *prep_stmt;

                /* Create a connection */
                driver = get_driver_instance();
                con = driver->connect("tcp://192.168.122.73:3306", "admin", "Digital77.");
                /* Connect to the MySQL test database */
                con->setSchema("user_credentials");

                prep_stmt = con->prepareStatement("INSERT INTO user(username, password) VALUES (?, ?)");
                prep_stmt->setString(1, username);
                prep_stmt->setString(2, password);

                res = prep_stmt->executeQuery();

                con->setSchema("user_data");

                prep_stmt = con->prepareStatement("INSERT INTO inventory(username, slot1, slot2, slot3) VALUES (?, ?, ?, ?)");
                prep_stmt->setString(1, username);
                prep_stmt->setString(2, "wooden_sword");
                prep_stmt->setString(3, "healing_potion");
                prep_stmt->setString(4, "boss1");

                res = prep_stmt->executeQuery();

                if (res->next()) {
                    std::cout << "Register success!" << std::endl;

                    

                    //std::cout << "Login successful!" << std::endl;
                    //send(clientSocket, "Login successful!", strlen("Login successful!"), 0);
                } else {
                    std::cout << "Register failed!" << std::endl;

                }
                
                
                
                delete prep_stmt;


                delete res;

                delete con;

            } catch (sql::SQLException &e) {
                std::cout << "# ERR: SQLException in " << __FILE__;
                std::cout << "(" << __FUNCTION__ << ") on line "
                    << __LINE__ << std::endl;
                std::cout << "# ERR: " << e.what();
                std::cout << " (MySQL error code: " << e.getErrorCode();
                std::cout << ", SQLState: " << e.getSQLState() <<
                    " )" << std::endl;
            }
        }
    }


    close(clientSocket);
}

int main() {
    int serverSocket, clientSocket;
    sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating server socket." << std::endl;
        return -1;
    }

    // Initialize server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error binding server socket." << std::endl;
        close(serverSocket);
        return -1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, MAX_CONNECTIONS) == -1) {
        std::cerr << "Error listening for connections." << std::endl;
        close(serverSocket);
        return -1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    while (true) {
        // Accept a new client connection
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == -1) {
            std::cerr << "Error accepting client connection." << std::endl;
            continue;
        }

        // Handle the client in a separate thread
        std::thread(handleClient, clientSocket).detach();
    }

    // Close the server socket
    close(serverSocket);

    return 0;
}















/*
int main() {
    // Create a socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    // Bind the socket to a port
    sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(12345);

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        close(serverSocket);
        return 1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, SOMAXCONN) < 0) {
        std::cerr << "Listen failed" << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "Server listening on port 12345..." << std::endl;

    // Accept and handle client connections in separate threads
    while (true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket < 0) {
            std::cerr << "Accept failed" << std::endl;
            close(serverSocket);
            return 1;
        }

        std::thread(handleClient, clientSocket).detach();
    }

    // Cleanup
    close(serverSocket);

    return 0;
}
*/