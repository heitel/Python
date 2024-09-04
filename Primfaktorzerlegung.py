

if __name__ == "__main__":
    head = "Dieses Programm findet die Primfaktorzerlegung einer Zahl."
    len = len(head)
    print(head)
    print("~" * len)
    print("Geben Sie bitte eine ganze Zahl ein: ", end="")
    zahl = int(input())
    print(f"Die Primfaktoren von {zahl} sind: ", end="")
    teiler = 2
    firstTime = True
    never = True
    for teiler in range(2, zahl):
        while zahl % teiler == 0:
            zahl //= teiler
            if not firstTime:
                print(" * ", end="")
            firstTime = False
            print(teiler, end="")
            never = False
    if never:
        print(f"\n\t{zahl} ist eine Primzahl.")