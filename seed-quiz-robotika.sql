-- Seed kuis untuk slug 'robotika' — sesuaikan title, passingGrade,
-- password (isi string kalau mau dikunci seperti 'rpl', atau NULL kalau
-- tidak dikunci), dan daftar soal/opsi/jawaban di bawah.
--
-- Catatan format "ans": nilai di file rpl adalah index jawaban benar
-- (dimulai dari 0) yang di-base64-kan, contoh: index 2 -> base64("2") = "Mg=="
--   index 0 -> "MA=="   index 1 -> "MQ=="   index 2 -> "Mg=="
--   index 3 -> "Mw=="   index 4 -> "NA=="   dst.

INSERT INTO quizzes (id, slug, title, passingGrade, password, questions) VALUES (
    'quiz_robotika',
    'robotika',
    'Evaluasi Kompetensi: Robotika',
    75,
    NULL,
    '[
        {"q":"Sensor apa yang umum digunakan untuk mengukur jarak pada robot line follower?","options":["Sensor infrared/IR","Sensor GPS","Sensor gyroscope","Sensor suhu"],"ans":"MA=="},
        {"q":"Komponen apa yang berfungsi sebagai otak pengendali pada robot mikrokontroler?","options":["Motor DC","Mikrokontroler (mis. Arduino/ESP32)","Baterai","Kabel jumper"],"ans":"MQ=="},
        {"q":"Apa fungsi utama motor driver (mis. L298N) pada rangkaian robot?","options":["Menyimpan program","Mengukur jarak","Mengatur arah & kecepatan motor DC","Mengirim data via WiFi"],"ans":"Mg=="}
    ]'
);
