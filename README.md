# Logarithm and expnential-function estimation in P4 language 


Installation
------------

1. Install [docker](https://docs.docker.com/engine/installation/) if you don't
   already have it.

2. Clone the repository to local 

    ```
    git clone https://github.com/DINGDAMU/Network-wide-heavy-hitter-detection
    ```

3. ```
    cd Network-wide-heavy-hitter-detection
   ```

4. If you want, put the `p4app` script somewhere in your path. For example:

    ```
    cp p4app /usr/local/bin
    ```
    I have already modified the default docker image to **dingdamu/p4app-ddos:nwhhd**, so `p4app` script can be used directly.

P4Log algorithm
--------------

1.  ```
    ./p4app run log.p4app 
    ```
    After this step you'll see the terminal of **mininet**
2. Forwarding some packets in **mininet**
   ```
    pingall
   ```
3. Enter log.p4app folder
   ```
    cd log.p4app 
   ```
4. Check the result by reading the register
   ```
    ./read_registers1.sh
   ```
5. `Register[0]` is the input value and `Register[1]` is the result of `log2(Register[0])` amplified $2^{10}$ times

P4Exp algorithm
--------------

1.  ```
    ./p4app run exp.p4app 
    ```
    After this step you'll see the terminal of **mininet**
2. Forwarding some packets in **mininet**
   ```
    pingall
   ```
3. Enter exp.p4app folder
   ```
    cd exp.p4app 
   ```
4. Check the result by reading the register
   ```
    ./read_registers1.sh
   ```
5. `Register[0]` is the base and `Register[1]` is the exponent, the exponential-function result is in `Register[2]` 

