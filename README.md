# akord-auth

Akord Authentication Provider

## Usage

### Import
```js
import { Auth } from "@akord/akord-auth";
```
or
```js
const { Auth } = require("@akord/akord-auth");
```

### Methods

#### `signIn(email, password)`

- `email` (`string`, required)
- `password` (`string`, required)
- returns `Promise<{ wallet }>` - Promise with an Akord Wallet

<details>
  <summary>example</summary>

```js
const { wallet } = await new Auth().signIn("winston@gmail.com", "1984");
```
</details>

#### `signUp(email, password)`

- `email` (`string`, required)
- `password` (`string`, required)
- returns `Promise<{ wallet }>` - Promise with an Akord Wallet

<details>
  <summary>example</summary>

```js
const { wallet } = await new Auth().signUp("winston@gmail.com", "1984");
```
</details>

#### `verifyAccount(email, code)`

- `email` (`string`, required)
- `code` (`string`, required)
- returns `Promise<void>`

<details>
  <summary>example</summary>

```js
await new Auth().verifyAccount("winston@gmail.com", 123456);
```
</details>

#### `refreshToken()`


### Development
```
yarn install
yarn build
```

To run tests:
```
node --inspect node_modules/.bin/jest ./src/__tests__/auth.test.ts
```
