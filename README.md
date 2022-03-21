# Nebula Graph Studio
Nebula Graph Studio (Studio for short) is a web-based visualization tool for Nebula Graph. With Studio, you can create a graph schema, import data, edit nGQL statements for data queries, and explore graphs.
![](./introduction.png)

## Architecture
![](architecture.png)

## Development Quick Start

### set up studio and server at the same time
```
$ npm install
$ npm run dev-all
```

### Set up nebula-graph-studio only
```
$ npm install
$ npm run dev
```
### Set up go-server only
```
$ cd server
$ go build -o server
$ nohup ./server &
```

## Production Deploy

### 1. Build Web
```
$ npm run install
$ npm run build
$ mv dist server/assets
```

### 2. Build Server
```
$ cd server
// update default port 9000 to 7001 in config/example-config.yaml first
$ go build -o server
```

### 3. Start
```
$ nohup ./server &
```

### 4. Stop Server
Use when you want shutdown the web app
```
kill -9 $(lsof -t -i :7001)
```

## Documentation 
[中文](https://docs.nebula-graph.com.cn/2.5.0/nebula-studio/about-studio/st-ug-what-is-graph-studio/)
[ENGLISH](https://https://docs.nebula-graph.io/2.5.0/nebula-studio/about-studio/st-ug-what-is-graph-studio/)

## Contributing
Contributions are warmly welcomed and greatly appreciated. Please see [Guide Docs](https://github.com/vesoft-inc-private/nebula-graph-studio/blob/master/CONTRIBUTING.md) 