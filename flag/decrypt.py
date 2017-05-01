from	Crypto.Cipher import AES

mods = "444546434F4E20435446202017204C696768746E696E67205761732048657265".decode("hex");

raw_data = open("data1", "rb").read();
key      = open("key", "rb").read();
iv       = open("iv", "rb").read();
new_key = "";
for idx, x in enumerate(key):
	x = ord(x) ^ ord(mods[idx]);
	new_key += chr(x);
key = new_key;

aes = AES.new(key, AES.MODE_CBC, iv);
data = aes.decrypt(raw_data);
print(data);
