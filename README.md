AES-GCM 128 Encryption Implementation

Sequential Code — Course Project

# Clone the repository
git clone https://github.com/Swargam-madhusudhan/AES_GCM_encryption_128.git
cd AES_GCM_encryption_128

# Create and enter the build directory
mkdir build  
cd build

# Configure the project
cmake ..  

# Build the executable
make

# Run the executable with sample input/output files
 ./AES_Encrypt_GCM_128_Seq -i ../Dataset/1/PT.dat -e ../Dataset/1/CT.dat -t vector

