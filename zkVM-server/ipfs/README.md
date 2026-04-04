# Getting started with IPFS
```
sudo chown -R 1000:1000 ./ipfs/ipfs_data
sudo chown -R 1000:1000 ./ipfs/ipfs_staging
```
Currently, our project IPFS run on the private network. Only with the private key `swarm.key` can access our private IPFS.
You can ask admin for the `swarm.key`. You should put the key in the directory `/ipfs_data`.
Foramlly, we run the IPFS from the `docker-compose.yml`, which is locate at the parent directory.