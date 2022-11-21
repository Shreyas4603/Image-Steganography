import base64
import math
import time
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from tkinter import ttk

from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from PIL import ImageTk

def encrypt(key, source, encode=True):  # key=password,source = message
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode() if encode else data


def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def to_binary(str):
    bin_arr = []
    lst = []
    for i in str:
        bin_arr.append(list((map(int, list(format(ord(i), '08b'))))))
    return bin_arr


def encodeImage(img, password, message, filename):
    width, height = img.size
    x, y = 0, 0
    char_count = 0  # counts how many chars have been encoded
    pix = list(img.getdata())
    curr_pix = 0  # pixel pointer
    if password != "":
        cipher = encrypt(password.encode(), message.encode())  # encrpting the message

        cipher = headerText + cipher

    else:
        cipher = message

    # print("ciper before entry : ",cipher)
    # str_bin=to_binary(cipher) #encrypted string to be stored in image
    # if len(cipher)==len(str_bin):
    #     print(len(cipher))
    itr = 1

    # try:
    for ch in cipher:
        time.sleep(0.1)

        progress_bar['value'] += (itr / len(cipher)) * 100
        percent_lab.configure(text=str(math.trunc(itr / len(cipher) * 100)) + " % Completed")
        root.update_idletasks()

        itr += 1

        byte_arr = to_binary(ch)

        byte_arr = byte_arr[0]

        p1 = pix[curr_pix]
        p2 = pix[curr_pix + 1]
        p3 = pix[curr_pix + 2]
        # ^^picking 3 pixels at a time and taking their RGB value

        three_pixel_data = [val for val in p1 + p2 + p3]  # combining those 3 rgb values to 1 array
        # print("--------------------------------------------------------")
        # print("Three pix data before update : ",three_pixel_data)
        for i in range(0, 8):
            curr_bit = byte_arr[i]
            if curr_bit == 0:
                if three_pixel_data[i] % 2 != 0:
                    three_pixel_data[i] = three_pixel_data[i] - 1 if three_pixel_data[i] == 255 else \
                        three_pixel_data[i] + 1
            elif curr_bit == 1:
                if three_pixel_data[i] % 2 == 0:
                    three_pixel_data[i] = three_pixel_data[i] - 1 if three_pixel_data[i] == 255 else \
                        three_pixel_data[i] + 1

        # print(curr_pix)
        char_count += 1
        curr_pix += 3

        if (char_count == len(cipher)):
            # Make as 1 (odd) - stop reading
            # print("Before end : ",three_pixel_data)
            if three_pixel_data[-1] % 2 == 0:
                three_pixel_data[-1] = three_pixel_data[-1] - 1 if three_pixel_data[-1] == 255 else \
                    three_pixel_data[-1] + 1
                # print("Pixel data ending :",three_pixel_data)
        else:
            # Make as 0 (even) - continue reading
            if three_pixel_data[-1] % 2 != 0:
                three_pixel_data[-1] = three_pixel_data[-1] - 1 if three_pixel_data[-1] == 255 else \
                    three_pixel_data[-1] + 1


        three_pixels = tuple(three_pixel_data)

        start = 0
        end = 3

        for i in range(0, 3):
            img.putpixel((x, y), three_pixels[start:end])
            start += 3
            end += 3

            if (x == width - 1):
                x = 0
                y += 1
            else:
                x += 1
        progress_bar.stop()
    encoded_filename = filename.split('.')[0] + "-enc.png"

    img.save(encoded_filename)


def decodeImage(img):
    pix = img.getdata()

    curr_pix = 0
    decoded_text = ""

    itr = 0
    try:
        while True:

            itr += 1
            bin_store = ""
            p1 = pix[curr_pix]
            p2 = pix[curr_pix + 1]
            p3 = pix[curr_pix + 2]

            three_pixels_data = [val for val in p1 + p2 + p3]

            for i in range(0, 8):

                if three_pixels_data[i] % 2 == 0:
                    bin_store += "0"
                elif three_pixels_data[i] % 2 != 0:
                    bin_store += "1"

            bin_store.strip()
            ascii_val = int(bin_store, 2)

            decoded_text += chr(ascii_val)


            curr_pix += 3

            if three_pixels_data[-1] % 2 != 0:
                # print(three_pixels_data)
                # print("iter = ",itr)

                break
        return (str(decoded_text))




    except:
        enc_log_label.configure(text="Error Occured couldn't decode , Try again")


def open_file(flip):
    filename = filedialog.askopenfilename(initialdir="/",
                                          title="Select image files",
                                          filetypes=(("Image files",
                                                      "*.png*"),
                                                     ("Image files",
                                                      "*.jpg*")))
    if flip == 0:
        file_add[0] = filename
        file_address_label.configure(text=filename)
    elif flip == 1:
        file_add[0] = filename
        decry_file_address_label.configure(text=filename)


def brain(switch):
    if (switch == 0):  # 0 when its encrpt
        # try:
        print(decry_password_var.get())

        img = ImageTk.Image.open(file_add[0])

        width, height = img.size

        if (len(message_var.get()) > (width * height)):
            enc_log_label.configure(text="Message too long....")

        # modified_img=img.save(file_add[0].replace(".png",".jpg"))
        if (".png" in file_add[0]):
            img = img.convert("RGB")

        encodeImage(img, password_var.get(), message_var.get(), file_add[0])

        enc_log_label.configure(text="Completed(Image saved in same directory as source)", fg="#00A023")

        # message_input.delete(0,"end")#clear input
        # except:s
        #     enc_log_label.configure(text="An Error occurred , Try Again")
    elif (switch == 1):  # 0 when its decrypt
        try:
            decry_img = ImageTk.Image.open(file_add[0])
            message = decodeImage(decry_img)
            decry_textbox.delete("1.0", "end")

            message = message[len(headerText):]

            passcode = decry_password_var.get()

            final_msg = decrypt(passcode.encode(), message)
            final_msg=final_msg.decode('ascii')
            decry_textbox.insert(1.0, str(final_msg))

            enc_log_label.configure(text="Decoding complete", fg="#000000")

        except Exception as w:

            enc_log_label.configure(text="An Error occurred , Try Again",
                                    fg="#000000")  # logs on the encry log label share same label

# -------------------------------MAIN-------------------------

if __name__ == "__main__":
    file_add = ["default_address"]  # shared by both decry n encry
    headerText = "M6nMjy5THr2J"
    log_data = ""

    root = Tk()
    root.title("Hide Image")
    # root.geometry('%dx%d+%d+%d' % (500, 700, 1400, 100))
    root.minsize(width=500, height=700)
    root.resizable(width=False, height=False)

    encode_label = Label(root, text="Encode Image", font="Verdana 13 bold", borderwidth=2, relief="solid", fg="#FF2E2E",
                         padx=3, pady=3)
    encode_label.place(x=180, y=80)

    heading_label = Label(root, text="Hide your message inside an image", font="Verdana 15 bold", padx=5, pady=5,
                          borderwidth=2, relief="solid")
    heading_label.place(x=50, y=28)

    message_label = Label(root, text="Message", font="Verdana 10")
    message_label.place(x=10, y=120)

    message_var = tk.StringVar()  # stores the message input
    message_input = Entry(root, textvariable=message_var, font="Verdana 10", width=50, highlightthickness=2,
                          highlightcolor="blue")
    message_input.place(x=80, y=121)

    password_var = tk.StringVar()  # stores the password input
    password_input = Entry(root, textvariable=password_var, font="Verdana 10", width=50, highlightthickness=2,
                           highlightcolor="blue", show="*")
    password_input.place(x=80, y=151)
    password_label = Label(root, text="Password", font="Verdana 10", borderwidth=3)
    password_label.place(x=10, y=151)

    button_select_file = Button(root, text="Browse Image", command=lambda: open_file(0))
    button_select_file.place(x=10, y=180)

    file_address_label = Label(root)
    file_address_label.place(x=100, y=184)

    enc_log_label = Label(root, borderwidth=1.3, relief="solid", width=54, height=2, font="verdana 10 bold",
                          justify="center",
                          fg='#f00')
    enc_log_label.place(x=5, y=300)

    button_brain = Button(root, text="Encrypt", command=lambda: brain(0), bg="#32CD32", fg="#ffffff",
                          font="Verdana 12 bold")
    button_brain.place(x=210, y=230)

    progress_bar = ttk.Progressbar(root, orient=HORIZONTAL, length=480)
    progress_bar.place(x=10, y=270)

    percent_lab = Label(root, font="Verdana 10")
    percent_lab.place(x=20, y=240)

    decode_label = Label(root, text="Decode Image", font="Verdana 13 bold", borderwidth=2, relief="solid", fg="#FF2E2E",
                         padx=3, pady=3)
    decode_label.place(x=180, y=350)

    decry_password_var = tk.StringVar()  # stores the password input
    decry_password_input = Entry(root, textvariable=decry_password_var, font="Verdana 10", width=50,
                                 highlightthickness=2,
                                 highlightcolor="blue", show="*")
    decry_password_input.place(x=80, y=400)
    decry_password_label = Label(root, text="Password", font="Verdana 10", borderwidth=3)
    decry_password_label.place(x=10, y=400)

    decry_button_select_file = Button(root, text="Browse Image", command=lambda: open_file(1))
    decry_button_select_file.place(x=10, y=430)

    decry_file_address_label = Label(root)
    decry_file_address_label.place(x=100, y=430)

    button_brain = Button(root, text="Decrypt", command=lambda: brain(1), bg="#32CD32", fg="#ffffff",
                          font="Verdana 12 bold")
    button_brain.place(x=210, y=460)

    decry_textbox = Text(root, height=10, width=60)
    decry_textbox.place(x=6, y=500)

    decry_label = Label(root, text="Decrypted Text", font="Verdana 10", borderwidth=3)
    decry_label.place(x=200, y=670)

    root.update()

    root.mainloop()