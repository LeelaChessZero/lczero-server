import os
import time
import glob

all_resign = []
d = 0
xd = 0
avg = 0
uploadpath = "/root/lczero-server/resign/run1"
games_per_net = 30000
resign_playthrough = 15
false_resign_rate = 5


while True:
  upload_path = os.path.join(uploadpath, '*')
  resigns = sorted(glob.iglob(upload_path), key=os.path.getmtime, reverse=True)
  print(resigns[0])
  for resign in resigns:
    if resign.endswith("txt"):
      d = d + 1
      s = open(resign, "r")
      s1 = s.read()
      all_resign.append(s1)
    if d > (games_per_net * resign_playthrough * .01):
      all_resign.sort()
      y = int(len(all_resign) / (100 / false_resign_rate))
      for i in range(y-5, y+4):
        xd += 1
        avg += float(all_resign[i])
      avg = round((avg/xd) * 100, 1)
      print("games: " + str(d))
      print(str(false_resign_rate) + "% false resigns @ resign rate: " + str(avg) + "%")
      break
  xd = 0
  avg = 0
  d = 0
  all_resign = []
  time.sleep(60*60*2)
    
