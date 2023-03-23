import { Auth } from "..";
import faker from '@faker-js/faker';

jest.setTimeout(3000000);

describe("Testing auth functions", () => {
  let auth: Auth;
  let email: string;
  let password: string;

  beforeAll(async () => {
    email = faker.internet.email();
    password = faker.internet.password();
  });

  it("should sign in", async () => {
    const { wallet } = await Auth.signIn(email, password);
    expect(wallet).toBeTruthy();
  });
});