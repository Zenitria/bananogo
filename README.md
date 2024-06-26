<hr>
<h1 align="center">BananoGo</h1>
<p align="center">Banano blockchain interaction library.</p>
<hr>

**Features:**
- Beginner-friendly functions (Send, Receive, ReceiveAll, ChangeRepresentative).
- Create, sign and process blocks.
- Send useful RPC requests.
- Send custom RPC requests.
- Unit conversion functions.
- Seed, Private Key, Public Key and Address conversion functions.
- Address validation.

You need another feature? Open an [issue](https://github.com/zenitria/bananogo/issues) with the `feature request` label.

<hr>

## Installation
Use `go get` to install the package.
```bash
go get github.com/zenitria/bannanogo@latest
```

## Example usage
```go
package main

import (
    "fmt"
    "github.com/zenitria/bananogo"
)

func main() {
    // Create a new client
    client := bananogo.Client{
        Url: "http://localhost:7076",
    }

    // Send Banano
    address := "ban_14kwyg4wxw89orxsxgzgrf14exwa683rmubth4i6uh1dnoir1kb48ip4zwdt"
    seed := "D2F1A4C8E7B0E3D5F2A1C8E0B7D3F8A0B2C4E5D7F9C2A3B6D9F3C0A1B2E5D4"
    raw, err := bananogo.BananoToRaw("0.01")

    if err != nil {
        fmt.Println(err)
        return
    }

    hash, err := client.Send(address, raw, seed, 0)

    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("Block hash:", hash)
}
```

<hr>

<h1 align="center">Short documentation</h1>
<p align="center">For more detailed documentation go to <a href="https://pkg.go.dev/github.com/zenitria/bananogo">pkg.go.dev</a></p>

<hr>

# Table of contents
- [RPC interaction](#rpc-interaction)
  - [Client](#client)
  - [Send](#send)
  - [Receive](#receive)
  - [Receive All](#receive-all)
  - [Change Representative](#change-representative)
  - [RPC](#rpc)
  - [Get Account Balance](#get-account-balance)
  - [Get Account Info](#get-account-info)
  - [Get Account History](#get-account-history)
  - [Get Receivable](#get-receivable)
  - [Get Representatives](#get-representatives)
  - [Generate Work](#generate-work)
  - [Process](#process)
- [Block creation and signing](#block-creation-and-signing)
  - [Block](#block)
  - [Sign](#sign)
  - [Add Work](#add-work)
- [Conversion](#conversion)
  - [Seed To Private Key](#seed-to-private-key)
  - [Private Key To Public Key](#private-key-to-public-key)
  - [Public Key To Address](#public-key-to-address)
  - [Address To Public Key](#address-to-public-key)
  - [Banano To Raw](#banano-to-raw)
  - [Raw To Banano](#raw-to-banano)
- [Validation](#validation)
  - [Address Is Valid](#address-is-valid)

# RPC interaction
## Client
The `Client` struct is used to interact with the Banano blockchain. It contains the URL of the RPC server, the authorization header and the authorization token.
```go
client := bananogo.Client{
    Url: "Banano RPC URL",
    AuthHeader: "Authorization header", // if the RPC server requires an authorization
    AuthToken: "Authorization token" // if the RPC server requires an authorization
}
```

## Send
The `Send` function sends Banano to an address. It requires the address, the raw amount, the seed and the account index. It returns the block hash or an error.
```go
hash, err := client.Send(address, raw, seed, index)
```

## Receive
The `Receive` function receives Banano from a block. It requires the block hash, the source address, the raw amount, the seed and the account index. It returns the block hash or an error.
```go
hash, err := client.Receive(hash, sourceAddress, raw, seed, index)
```

## Receive All
The `ReceiveAll` function receives all pending Banano. It requires the seed and the account index. It returns the block hashes or an error.
```go
hashes, err := client.ReceiveAll(seed, index)
```

## Change Representative
The `ChangeRepresentative` function changes the representative of an account. It requires the new representative, the seed and the account index. It returns the block hash or an error.
```go
hash, err := client.ChangeRepresentative(representative, seed, index)
```

## RPC
The `RPC` function sends a custom RPC request. It requires the data to send. It returns the response or an error.
```go
response, err := client.RPC(data)
```

## Get Account Balance
The `GetAccountBalance` function gets the balance of an account. It requires the address. It returns the balance or an error.
```go
balance, err := client.GetAccountBalance(address)
```

## Get Account Info
The `GetAccountInfo` function gets the information of an account. It requires the address. It returns the account info or an error.
```go
info, err := client.GetAccountInfo(address)
```

## Get Account History
The `GetAccountHistory` function gets the history of an account. It requires the address and the count (use -1 for all). It returns the account history or an error.
```go
history, err := client.GetAccountHistory(address, count)
```

## Get Receivable
The `GetReceivable` function gets the receivable blocks of an account. It requires the address. It returns the receivable blocks or an error.
```go
receivable, err := client.GetReceivable(address)
```

## Get Representatives
The `GetRepresentatives` function gets the online representatives. It returns the representatives or an error.
```go
representatives, err := client.GetRepresentatives()
```

## Generate Work
The `GenerateWork` function generates a work for a block hash. It requires the block. It returns the work or an error.
```go
work, err := client.GenerateWork(block)
```

## Process
The `Process` function processes a block. It requires the subtype and the block. It returns the block hash or an error.
```go
hash, err := client.Process(subtype, block)
```

# Block creation and signing
## Block
The `Block` struct is used to create and sign blocks. It contains the type, the account, the previous block hash, the representative, the balance, the link, the link as account, the signature and the work.
```go
block := bananogo.Block{
    Type: "type",
    Account: "wallet address",
    Previous: "previous block hash",
    Representative: "representative wallet address",
    Balance: "new balance in raw",
    Link: "link in hex",
    LinkAsAccount: "link as a wallet address",
    Signature: "block signature", // added after signing (not add manually)
    Work: "generated work", // added after generating work  (not add manually)
}
``` 
## Sign
The `Sign` function signs a block. It requires the private key. It optionally returns an error.
```go
err := block.Sign(privateKey)
```

## Add Work
The `AddWork` function adds work to a block. It requires the work.
```go
block.AddWork(work)
```

# Conversion
## Seed To Private Key
The `SeedToPrivateKey` function converts a seed to a private key. It requires the seed and the account index. It returns the private key or an error.
```go
privateKey, err := bananogo.SeedToPrivateKey(seed, index)
```

## Private Key To Public Key
The `PrivateKeyToPublicKey` function converts a private key to a public key. It requires the private key. It returns the public key or an error.
```go
publicKey, err := bananogo.PrivateKeyToPublicKey(privateKey)
```

## Public Key To Address
The `PublicKeyToAddress` function converts a public key to the wallet address. It requires the public key. It returns the address or an error.
```go
address, err := bananogo.PublicKeyToAddress(publicKey)
```

## Address To Public Key
The `AddressToPublicKey` function converts a wallet address to a public key. It requires the address. It returns the public key or an error.
```go
publicKey, err := bananogo.AddressToPublicKey(address)
```

## Banano To Raw
The `BananoToRaw` function converts Banano to raw. It requires the amount. It returns the raw amount or an error.
```go
raw, err := bananogo.BananoToRaw(amount)
```

## Raw To Banano
The `RawToBanano` function converts raw to Banano. It requires the raw amount. It returns the amount or an error.
```go
banano, err := bananogo.RawToBanano(raw)
```

# Validation
## Address Is Valid
The `AddressIsValid` function checks if a wallet address is valid. It requires the address. It returns a boolean.
```go
isValid := bananogo.AddressIsValid(address)
```