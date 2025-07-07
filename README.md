# Secure Messaging System

## 📚 Description

A Java-based client-server messaging system with end-to-end encryption, using AES, RSA, and the Double Ratchet algorithm. Backed by a MariaDB SQL database.


## 📁 File Structure

src/ <br>
└── src/ <br>
├── CreateDataBase.sql <br>
├── CreateTables.sql <br>
└── org/ <br>
├── Client/ <br>
│ ├── Main.java <br>
│ └── DoubleRatchetState.java <br>
├── Packets/ <br>
│ ├── AESAnswer.java <br>
│ ├── AESFinal.java <br>
│ ├── AESRequest.java <br>
│ ├── BundleRequestPacket.java <br>
│ ├── DirectMessagePacket.java <br>
│ ├── HandShake2Packet.java <br>
│ ├── HandShakeAlreadyMade.java <br>
│ ├── HandShakePacket.java <br>
│ ├── InfoPacket.java <br>
│ ├── KeyBundle.java <br>
│ ├── LoginPacket.java <br>
│ ├── MadeHand.java <br>
│ ├── MessagePacket.java <br>
│ ├── Packet.java <br>
│ ├── PacketUtils.java <br>
│ ├── PublicKeyPacket.java <br>
│ ├── RegisterPacket.java <br>
│ ├── UserListPacket.java <br>
│ ├── UserListRequestPacket.java <br>
│ ├── UserSelect.java <br>
│ ├── oneTimeKeysPacket.java <br>
├── Keys/ <br>
│ ├── RSAKeys.java <br>
│ └── AESKeys.java <br>
├── Server/ <br> 
│ ├── Main.java <br>
└── DataBase/ <br>
└── DBConnect.java <br>


## 🛠️ Database Setup (MariaDB)

1. Install [MariaDB](https://mariadb.org/download/).
2. Run the SQL scripts:

```bash
mysql -u your_username -p < src/src/CreateDataBase.sql
mysql -u your_username -p your_database_name < src/src/CreateTables.sql
```

Configure your credentials inside:

```bash
src/src/org/DataBase/DBConnect.java
```

## 🚀 Run the Server

```bash
cd src/src
javac org/Server/*.java org/Packets/*.java org/Keys/*.java org/DataBase/*.java
java org.Server.Main
```

## 💻 Run the Client

```bash
cd src/src
javac org/Client/*.java org/Packets/*.java org/Keys/*.java
java org.Client.Main
```

## 🧪 Features
- 🔐 End-to-end encryption with Double Ratchet

- 💬 Direct & secure messaging

- 🧾 Registration, login, key exchange

- 🗄️ MariaDB-based user/key storage
