

if __name__ == "__main__":
    head = "Dieses Programm findet alle Teiler einer Zahl."
    len = len(head)
    print(head)
    print("=" * len)
    print("Geben Sie bitte eine ganze Zahl ein: ", end="")
    zahl = int(input())
    print(f"Die Teiler von {zahl} sind:")
    teiler = 2
    count = 0
    while teiler < zahl:
        if zahl % teiler == 0:
            print(teiler, " ", end="")
            count += 1
        teiler += 1
    if count == 0:
        print(f"\t{zahl} ist eine Primzahl")
