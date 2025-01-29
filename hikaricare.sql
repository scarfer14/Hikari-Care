-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jan 26, 2025 at 06:52 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `hikaricare`
--

-- --------------------------------------------------------

--
-- Table structure for table `appointments`
--

CREATE TABLE `appointments` (
  `appointment_id` varchar(11) NOT NULL,
  `patient_id` varchar(8) NOT NULL,
  `doctor_id` varchar(8) NOT NULL,
  `appointment_date` datetime NOT NULL,
  `reason` text DEFAULT NULL,
  `status` enum('Scheduled','Completed','Canceled') NOT NULL DEFAULT 'Scheduled',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `appointments`
--

INSERT INTO `appointments` (`appointment_id`, `patient_id`, `doctor_id`, `appointment_date`, `reason`, `status`, `created_at`) VALUES
('A14015', 'PID31517', '20240004', '2024-12-25 00:30:00', 'Persistent cold symptoms', 'Scheduled', '2024-12-15 21:35:19'),
('A20742', 'PID87180', '20240004', '2025-01-31 08:42:00', 'Rashes', 'Scheduled', '2025-01-26 01:39:53'),
('A56748', 'PID07539', '20250003', '2025-01-26 20:51:00', 'Coughing for 2 weeks', 'Scheduled', '2025-01-26 12:51:16'),
('A59810', 'PID07539', '20250003', '2025-01-30 11:54:00', 'painful urination', 'Scheduled', '2025-01-26 12:51:26'),
('A65635', 'PID31517', '20240004', '2025-01-24 22:22:00', 'fdasfdasfadfasdf', 'Scheduled', '2025-01-23 17:20:47'),
('A89687', 'PID31517', '20240004', '2024-12-31 00:30:00', 'Persistent cold symptoms', 'Completed', '2024-12-16 05:31:29'),
('A96729', 'PID32280', '20240004', '2025-01-28 00:26:00', 'Coughing for 2 weeks', 'Scheduled', '2025-01-23 17:25:45');

-- --------------------------------------------------------

--
-- Table structure for table `failed_logins`
--

CREATE TABLE `failed_logins` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `failed_attempts` int(11) NOT NULL DEFAULT 0,
  `last_failed_attempt` datetime NOT NULL,
  `locked_until` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `patients`
--

CREATE TABLE `patients` (
  `patient_id` varchar(8) NOT NULL,
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) NOT NULL,
  `date_of_birth` date NOT NULL,
  `gender` enum('Male','Female','Other') NOT NULL,
  `address` text NOT NULL,
  `phone_number` varchar(20) NOT NULL,
  `email` varchar(100) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `patients`
--

INSERT INTO `patients` (`patient_id`, `first_name`, `last_name`, `date_of_birth`, `gender`, `address`, `phone_number`, `email`, `created_at`) VALUES
('PID07539', 'Maki', 'Tsukimoto', '2025-01-22', 'Female', 'Miyagino-ku, Sendai', '9821337582', 'tsukimoto81@gmail.com', '2025-01-26 12:50:56'),
('PID10498', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:47:42'),
('PID16293', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:24:14'),
('PID21314', 'John', 'Cruz', '1993-02-10', 'Male', 'Sampaloc, Manila', '9123034413', 'cruzjohn@gmail.com', '2024-12-10 17:48:11'),
('PID27535', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:30:22'),
('PID29457', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:27:15'),
('PID31517', 'Eric', 'Mananquil', '1995-07-05', 'Male', 'Sampaloc, Manila', '9123034411', 'mananquil@gmail.com', '2024-12-10 17:37:16'),
('PID32280', 'Josh', 'Budiao', '1995-07-05', 'Male', 'Fairview, Quezon City', '9123034411', 'jonbudi@gmail.com', '2024-12-10 17:35:18'),
('PID37316', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:46:24'),
('PID39535', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:17:06'),
('PID39560', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:37:50'),
('PID44545', 'Judy Ann', 'Morata', '2000-11-01', 'Male', '11 Carreon, Novaliches, Quezon City', '9821337582', 'morata123@gmail.com', '2025-01-23 16:53:43'),
('PID72058', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:30:08'),
('PID87180', 'Maki', 'Tsukimoto', '1981-07-09', 'Female', 'Miyagino-ku, Sendai', '9821342321', 'tsukimoto81@gmail.com', '2024-11-25 17:39:16'),
('PID95804', 'Angelie', 'Jang', '2001-09-19', 'Female', 'Sampaloc, Manila', '09821342321', 'jangwan21@gmail.com', '2025-01-26 17:33:17');

-- --------------------------------------------------------

--
-- Table structure for table `records`
--

CREATE TABLE `records` (
  `record_id` varchar(11) NOT NULL,
  `patient_id` varchar(8) NOT NULL,
  `doctor_id` varchar(8) NOT NULL,
  `visit_date` datetime NOT NULL,
  `diagnosis` text DEFAULT NULL,
  `treatment` text DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `records`
--

INSERT INTO `records` (`record_id`, `patient_id`, `doctor_id`, `visit_date`, `diagnosis`, `treatment`, `notes`, `created_at`) VALUES
('R202500002', 'PID31517', '20240004', '2024-12-17 10:32:00', 'persistent dry cough caused by upper respiratory tract infection', 'Recommend over the counter cough suppressants and increase fluid intake', 'Advised the patient to monitor for additional symptoms. Follow up check-up is required within 1-2 weeks', '2024-12-16 18:35:05'),
('R202500003', 'PID31517', '20240004', '2024-12-26 11:47:00', 'erwers', 'dfasdfa', 'gaeawer', '2024-12-16 19:51:09'),
('R202500004', 'PID21314', '20240004', '2025-02-05 11:51:00', 'dfadfa', 'grfwedsfasd', 'fasdwe', '2024-12-16 19:52:27'),
('R202500005', 'PID31517', '20240004', '2024-12-05 12:06:00', 'dfadfadfgadfaEFASDCADRFAEFADF', 'ADFADFWAEFASD', 'FASRFFDFASD', '2024-12-16 20:08:54'),
('R202500006', 'PID21314', '20240004', '2024-12-17 10:26:00', 'persistent cold symptoms likely due to allergic rhinitis', 'recommended nasal spray for congestion', 'schedule follow-up in 1-2 weeks', '2024-12-16 10:27:56'),
('R202500007', 'PID87180', '20250003', '2025-01-27 00:49:00', 'urinalysis show positive for urinary tract infection', 'Sulfonamides antibiotics once a day for 1 week', 'required for a check up next next week', '2025-01-26 16:51:07'),
('R202500008', 'PID87180', '20250003', '2025-01-27 00:49:00', 'urinalysis show positive for urinary tract infection', 'Sulfonamides antibiotics once a day for 1 week', 'required for a check up next next week', '2025-01-26 16:53:52'),
('R202500009', 'PID87180', '20250003', '2025-01-27 00:49:00', 'urinalysis show positive for urinary tract infection', 'Sulfonamides antibiotics once a day for 1 week', 'required for a check up next next week', '2025-01-26 16:55:27');

--
-- Triggers `records`
--
DELIMITER $$
CREATE TRIGGER `generate_record_id` BEFORE INSERT ON `records` FOR EACH ROW BEGIN
    DECLARE last_id INT;
    DECLARE year_prefix CHAR(5);

    -- Get the current year as a prefix
    SET year_prefix = CONCAT('R', YEAR(CURDATE()));

    -- Find the maximum sequence number for the current year
    SELECT COALESCE(MAX(CAST(SUBSTRING(record_id, 6) AS UNSIGNED)), 0)
    INTO last_id
    FROM records
    WHERE record_id LIKE CONCAT(year_prefix, '%');

    -- Increment the sequence number and set the new record ID
    SET NEW.record_id = CONCAT(year_prefix, LPAD(last_id + 1, 5, '0'));
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `sessions`
--

CREATE TABLE `sessions` (
  `session_id` varchar(255) NOT NULL,
  `user_id` int(11) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_activity` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `sessions`
--

INSERT INTO `sessions` (`session_id`, `user_id`, `created_at`, `last_activity`) VALUES
('0n1tmg4qkd3t31ck34dhvj5v45', 20240003, '2025-01-26 09:17:25', '2025-01-26 09:17:25'),
('16287ru2j2clh8ugsgou8s22d8', 20240003, '2025-01-26 09:29:08', '2025-01-26 09:29:08'),
('1nnipk3358c8g4d7n54nvt8isf', 20240001, '2025-01-26 08:30:00', '2025-01-26 08:30:00'),
('4fjbpnc1i4ctgrk1blgs4d30op', 20240004, '2025-01-26 10:08:54', '2025-01-26 10:08:54'),
('57c2oh41taigp38jeekl2da9ur', 20250001, '2025-01-26 15:21:27', '2025-01-26 15:21:27'),
('5qeiq05h3mlscjui6b7t5nehbn', 20240005, '2025-01-26 08:40:58', '2025-01-26 08:40:58'),
('63hpvv1gls0bntjcrrk1t1il1t', 20250001, '2025-01-26 16:20:33', '2025-01-26 16:20:33'),
('6uqapjm3c08fnn05knc5lh6nig', 20250003, '2025-01-26 17:15:45', '2025-01-26 17:15:45'),
('82jh3n30e79vnpjr37scf6dibq', 20240005, '2025-01-26 07:53:38', '2025-01-26 07:53:38'),
('88ev7be6neqqseiloijl1vkkfe', 20250001, '2025-01-26 15:49:54', '2025-01-26 15:49:54'),
('93b0e3421vck61i568c5tmk5uu', 20250006, '2025-01-26 15:19:16', '2025-01-26 15:19:16'),
('9lvpcnl0qmo8t6opsksd2ie7od', 20250001, '2025-01-26 14:11:07', '2025-01-26 14:11:07'),
('becbibi8c5jiigrpqvp9ul3fof', 20240001, '2025-01-26 08:39:23', '2025-01-26 08:39:23'),
('c94u0g2nd9hhkol7988a1nub61', 20250001, '2025-01-26 16:03:39', '2025-01-26 16:03:39'),
('di3givumi43febkjvectuj4s4l', 20250001, '2025-01-26 14:56:37', '2025-01-26 14:56:37'),
('esr4vqd4c003tmgkpqbehv958o', 20250002, '2025-01-26 13:50:36', '2025-01-26 13:50:36'),
('hsv4ko3l0d8n1v86p6qr6j8pue', 20250002, '2025-01-26 18:02:04', '2025-01-26 18:02:04'),
('ij6f56njs0v39bmm8sn2aj9jlg', 20250001, '2025-01-26 16:45:28', '2025-01-26 16:45:28'),
('ilb2ecadv5itf9bj8si8ca4aq2', 20240001, '2025-01-26 08:04:07', '2025-01-26 08:04:07'),
('jtk4gqq8vcnnfvoa08gqpok8ur', 20240003, '2025-01-26 07:57:42', '2025-01-26 07:57:42'),
('l6jqpc35c8m7rl2ftibd988h0l', 20250005, '2025-01-26 14:12:14', '2025-01-26 14:12:14'),
('lgsql0puqu1pvibkn9j6f9p35h', 20250001, '2025-01-26 13:52:26', '2025-01-26 13:52:26'),
('oma9dkgbao1c735a4f90rnnkkr', 20240004, '2025-01-26 07:58:39', '2025-01-26 07:58:39'),
('povsnnhhf7rvpotr4cnmm6jr90', 20250001, '2025-01-26 15:47:20', '2025-01-26 15:47:20'),
('ptbkjdltvq0a02j0k42eu1pr2e', 20240003, '2025-01-26 09:11:16', '2025-01-26 09:11:16'),
('r9sfvt4pc7q19obcg2anpgv1u7', 20250001, '2025-01-26 14:44:03', '2025-01-26 14:44:03'),
('sc4dnfrl7q6avrvaocptrmlaeb', 20240004, '2025-01-26 09:40:26', '2025-01-26 09:40:26'),
('uvh6dl993aorf6nn8d5gsptudd', 20250001, '2025-01-26 15:39:44', '2025-01-26 15:39:44');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `user_id` varchar(8) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('Admin','Doctor','Receptionist') NOT NULL,
  `full_name` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `phone_number` varchar(20) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `username`, `password`, `role`, `full_name`, `email`, `phone_number`, `created_at`) VALUES
('20250001', 'hikariadmin', '$2y$10$QpU1qmUCSejfu9oPc0rAvONuvBASJjRZN8Ddaz2DQ0YQT3GHFmkCu', 'Admin', 'Hikari Care', 'hikaricare@gmail.com', '2147483647', '2024-12-05 17:55:14'),
('20250002', 'receptionist1', '$2y$10$5JSuRNPNstmQjNqw2jhkSO0QVhcM9aZ8jfc5Myh2HHfscz7SNot5C', 'Receptionist', 'Receptionist', '', '0', '2024-12-06 15:32:28'),
('20250003', 'docchan', '$2y$10$VWClP0if/XgPU/GbYxr2ku/aIHT6o6NBUSeRTKkFMn9ouMuQq9DfO', 'Doctor', 'Jose Chan', 'chanjose@gmail.com', '2147483647', '2024-12-10 18:40:36'),
('20250004', 'hikariaccess', '$2y$10$E4sSE2MbozABwZsIN0l.BOtXDR4hV76nmg1zR/U.R.7jEPbk5ErEG', 'Admin', 'Hikari Care', 'hikaricare@gmail.com', '0', '2024-12-16 23:45:29'),
('20250005', 'receptionist2', '$2y$10$Sh1ytLZKZ7TmdtGGTSX6fe1Zjdm0rhZpeTNH3HA4HbXYEd4x7paBO', 'Receptionist', '', '', '0', '2025-01-26 12:52:56'),
('20250006', 'doccruz', '$2y$10$kZHcm.C19YcDxiPdGyXUjeltq6U0NHeOBKlTysRDheY0iuFBhrQI.', 'Doctor', 'Choi Cruz', 'cruzchoi@gmail.com', '09892712837', '2025-01-26 13:11:22');

--
-- Triggers `users`
--
DELIMITER $$
CREATE TRIGGER `before_user_insert` BEFORE INSERT ON `users` FOR EACH ROW BEGIN
    DECLARE current_year CHAR(4);
    DECLARE next_id INT;

    -- Get the current year
    SET current_year = YEAR(CURDATE());

    -- Find the last inserted ID for the current year
    SELECT IFNULL(MAX(CAST(SUBSTRING(user_id, 5, 4) AS UNSIGNED)), 0) + 1
    INTO next_id
    FROM users
    WHERE SUBSTRING(user_id, 1, 4) = current_year;

    -- Generate the new user_id
    SET NEW.user_id = CONCAT(current_year, LPAD(next_id, 4, '0'));
END
$$
DELIMITER ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `appointments`
--
ALTER TABLE `appointments`
  ADD PRIMARY KEY (`appointment_id`);

--
-- Indexes for table `failed_logins`
--
ALTER TABLE `failed_logins`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `patients`
--
ALTER TABLE `patients`
  ADD PRIMARY KEY (`patient_id`);

--
-- Indexes for table `records`
--
ALTER TABLE `records`
  ADD PRIMARY KEY (`record_id`);

--
-- Indexes for table `sessions`
--
ALTER TABLE `sessions`
  ADD PRIMARY KEY (`session_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `failed_logins`
--
ALTER TABLE `failed_logins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
