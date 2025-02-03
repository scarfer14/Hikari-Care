-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Feb 03, 2025 at 02:13 PM
-- Server version: 10.11.10-MariaDB
-- PHP Version: 7.2.34

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `u415861906_infosec2235`
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
('A14015', 'PID31517', '20240004', '2024-12-25 00:30:00', 'Persistent cold symptoms', 'Scheduled', '2024-12-16 05:35:19'),
('A20742', 'PID87180', '20240004', '2025-01-31 08:42:00', 'Rashes', 'Scheduled', '2025-01-26 01:39:53'),
('A56748', 'PID07539', '20250003', '2025-01-26 20:51:00', 'Coughing for 2 weeks', 'Scheduled', '2025-01-26 12:51:16'),
('A59810', 'PID07539', '20250003', '2025-01-30 11:54:00', 'painful urination', 'Scheduled', '2025-01-26 12:51:26'),
('A65635', 'PID31517', '20240004', '2025-01-24 22:22:00', 'fdasfdasfadfasdf', 'Scheduled', '2025-01-23 17:20:47'),
('A89687', 'PID31517', '20240004', '2024-12-31 00:30:00', 'Persistent cold symptoms', 'Completed', '2024-12-16 05:31:29'),
('A96729', 'PID32280', '20240004', '2025-01-28 00:26:00', 'Coughing for 2 weeks', 'Scheduled', '2025-01-23 17:25:45');

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `event_type` enum('failed_login','successful_login','account_locked') NOT NULL,
  `event_time` datetime DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `audit_logs`
--

INSERT INTO `audit_logs` (`id`, `username`, `event_type`, `event_time`, `ip_address`, `user_agent`) VALUES
(1, 'receptionist1', 'successful_login', '2025-02-02 12:11:26', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(2, 'receptionist1', 'failed_login', '2025-02-02 12:18:26', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(3, 'docchan', 'failed_login', '2025-02-02 13:25:31', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(4, 'docchan', 'successful_login', '2025-02-02 13:25:36', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(5, 'receptionist2', 'failed_login', '2025-02-03 07:39:19', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(6, 'receptionist2', 'failed_login', '2025-02-03 07:39:24', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(7, 'receptionist2', 'failed_login', '2025-02-03 07:39:29', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(8, 'receptionist2', 'failed_login', '2025-02-03 07:39:40', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(9, 'receptionist2', 'failed_login', '2025-02-03 07:39:46', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(10, 'receptionist2', 'failed_login', '2025-02-03 07:39:52', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(11, 'receptionist2', 'failed_login', '2025-02-03 07:45:01', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(12, 'receptionist2', 'failed_login', '2025-02-03 07:45:05', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(13, 'receptionist2', 'failed_login', '2025-02-03 07:45:31', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(14, 'receptionist2', 'failed_login', '2025-02-03 07:45:40', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(15, 'hikariadmin', 'successful_login', '2025-02-03 08:06:12', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(16, 'docchan', 'successful_login', '2025-02-03 08:49:32', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(17, 'receptionist1', 'successful_login', '2025-02-03 09:12:26', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(18, 'receptionist1', 'successful_login', '2025-02-03 09:25:09', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(19, 'receptionist1', 'successful_login', '2025-02-03 09:32:54', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(20, 'receptionist1', 'failed_login', '2025-02-03 09:34:07', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(21, 'receptionist1', 'failed_login', '2025-02-03 09:43:38', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(22, 'receptionist1', 'failed_login', '2025-02-03 09:44:14', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(23, 'receptionist1', 'successful_login', '2025-02-03 09:44:40', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(24, 'receptionist3', 'failed_login', '2025-02-03 09:45:36', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(25, 'docchan', 'successful_login', '2025-02-03 09:53:38', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(26, 'receptionist1', 'successful_login', '2025-02-03 09:55:47', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(27, 'receptionist1', 'successful_login', '2025-02-03 09:59:20', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(28, 'hikariadmin', 'successful_login', '2025-02-03 10:13:38', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(29, 'hikariadmin', 'successful_login', '2025-02-03 10:20:35', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(30, 'receptionist1', 'successful_login', '2025-02-03 10:23:28', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(31, 'receptionist1', 'failed_login', '2025-02-03 10:23:46', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(32, 'receptionist1', 'successful_login', '2025-02-03 10:31:19', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(33, 'receptionist2', 'successful_login', '2025-02-03 10:33:25', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(34, 'hikariadmin', 'successful_login', '2025-02-03 13:03:13', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(35, 'receptionist2', 'failed_login', '2025-02-03 13:09:35', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(36, 'receptionist3', 'failed_login', '2025-02-03 13:09:40', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(37, 'hikariadmin', 'successful_login', '2025-02-03 13:09:49', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(38, 'receptionist1', 'successful_login', '2025-02-03 13:29:35', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(39, 'receptionist1', 'successful_login', '2025-02-03 13:39:29', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(40, 'hikariadmin', 'successful_login', '2025-02-03 13:39:36', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(41, 'hikariadmin', 'successful_login', '2025-02-03 13:42:56', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(42, 'hikariaccess', 'successful_login', '2025-02-03 13:43:03', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'),
(43, 'docchan', 'successful_login', '2025-02-03 13:47:24', '180.190.40.201', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36');

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

--
-- Dumping data for table `failed_logins`
--

INSERT INTO `failed_logins` (`id`, `username`, `failed_attempts`, `last_failed_attempt`, `locked_until`) VALUES
(17, 'receptionist3', 2, '2025-02-03 13:09:40', NULL),
(19, 'receptionist2', 1, '2025-02-03 13:09:35', NULL);

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
('PID07539', 'Maki', 'Tsukimoto', '2025-01-22', 'Female', 'Miyagino-ku, Sendai', '09821337582', 'tsukimoto81@gmail.com', '2025-01-26 12:50:56'),
('PID21314', 'John', 'Cruz', '1993-02-10', 'Male', 'Sampaloc, Manila', '9123034413', 'cruzjohn@gmail.com', '2024-12-10 17:48:11'),
('PID31517', 'Eric', 'Mendoza', '1995-07-05', 'Male', 'Sampaloc, Manila', '09123034411', 'mananquil@gmail.com', '2024-12-10 17:37:16'),
('PID32280', 'Josh', 'Budiao', '1995-07-05', 'Male', 'Fairview, Quezon City', '9123034411', 'jonbudi@gmail.com', '2024-12-10 17:35:18'),
('PID44545', 'Judy Ann', 'Morata', '2000-11-01', 'Male', '11 Carreon, Novaliches, Quezon City', '9821337582', 'morata123@gmail.com', '2025-01-23 16:53:43'),
('PID81134', 'Kevin', 'Manaloto', '2005-07-03', 'Male', 'Fairview, Quezon City', '09821322121', 'manaloto05@gmail.com', '2025-02-03 10:34:40'),
('PID87180', 'Maki', 'Tsukimoto', '1981-07-09', 'Female', 'Miyagino-ku, Sendai', '9821342321', 'tsukimoto81@gmail.com', '2025-01-26 01:39:16');

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
('R202500001', 'PID21314', '20240004', '2024-12-17 10:26:00', 'persistent cold symptoms likely due to allergic rhinitis', 'recommended nasal spray for congestion', 'schedule follow-up in 1-2 weeks', '2024-12-16 18:27:56'),
('R202500002', 'PID31517', '20240004', '2024-12-17 10:32:00', 'persistent dry cough caused by upper respiratory tract infection', 'Recommend over the counter cough suppressants and increase fluid intake', 'Advised the patient to monitor for additional symptoms. Follow up check-up is required within 1-2 weeks', '2024-12-16 18:35:05'),
('R202500003', 'PID31517', '20240004', '2024-12-26 11:47:00', 'erwers', 'dfasdfa', 'gaeawer', '2024-12-16 19:51:09'),
('R202500004', 'PID21314', '20240004', '2025-02-05 11:51:00', 'dfadfa', 'grfwedsfasd', 'fasdwe', '2024-12-16 19:52:27'),
('R202500005', 'PID31517', '20240004', '2024-12-05 12:06:00', 'dfadfadfgadfaEFASDCADRFAEFADF', 'ADFADFWAEFASD', 'FASRFFDFASD', '2024-12-16 20:08:54');

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
('09mj6lgji87nm3vnps2r7d15l2', 20250005, '2025-02-02 13:22:56', '2025-02-02 13:22:56'),
('0n1tmg4qkd3t31ck34dhvj5v45', 20240003, '2025-01-26 09:17:25', '2025-01-26 09:17:25'),
('0um8qb1u94jdd5radc9g3ppms8', 20250001, '2025-01-29 13:41:54', '2025-01-29 13:41:54'),
('16287ru2j2clh8ugsgou8s22d8', 20240003, '2025-01-26 09:29:08', '2025-01-26 09:29:08'),
('1gmcajrjmgtivtkncekt969n2l', 20250002, '2025-02-01 14:31:49', '2025-02-01 14:31:49'),
('1nnipk3358c8g4d7n54nvt8isf', 20240001, '2025-01-26 08:30:00', '2025-01-26 08:30:00'),
('23a3b2nb3h3s13esrehmji9pv7', 20250002, '2025-02-03 10:23:28', '2025-02-03 10:23:28'),
('23vp50a6jj88u54tv7gq5ktasf', 20250002, '2025-01-29 13:51:57', '2025-01-29 13:51:57'),
('240q7b82fpsbi7s9ik18u6ipiu', 20250002, '2025-02-02 12:11:26', '2025-02-02 12:11:26'),
('3aq59rapsa6cemn21ep4penrkf', 20250002, '2025-01-29 13:14:01', '2025-01-29 13:14:01'),
('3k7sda2tv1912usjebpgcthd42', 20250003, '2025-02-03 08:49:32', '2025-02-03 08:49:32'),
('3tih5qql5bp0rcjmgi4iujm2k2', 20250002, '2025-01-29 13:50:16', '2025-01-29 13:50:16'),
('4fjbpnc1i4ctgrk1blgs4d30op', 20240004, '2025-01-26 10:08:54', '2025-01-26 10:08:54'),
('4uejvkmguk1mnndtlnr47u9kko', 20250001, '2025-02-03 13:09:49', '2025-02-03 13:09:49'),
('51b6a22lq9cg99a87adih0f674', 20250002, '2025-02-03 09:25:09', '2025-02-03 09:25:09'),
('5qeiq05h3mlscjui6b7t5nehbn', 20240005, '2025-01-26 08:40:58', '2025-01-26 08:40:58'),
('621l4rc2aq9891cassrtgt1ur9', 20250001, '2025-02-01 13:50:28', '2025-02-01 13:50:28'),
('6psphp9g54tb55of1n87eramai', 20250003, '2025-02-03 09:53:38', '2025-02-03 09:53:38'),
('6vunm281a1djue00insjvhpqs1', 20250001, '2025-02-03 13:39:36', '2025-02-03 13:39:36'),
('7caqd6j35kp22ag7vrtcnrjhh3', 20250001, '2025-02-03 10:13:38', '2025-02-03 10:13:38'),
('82jh3n30e79vnpjr37scf6dibq', 20240005, '2025-01-26 07:53:38', '2025-01-26 07:53:38'),
('9d6klmqtedh0djgrk6mouvsid1', 20250002, '2025-02-03 09:44:40', '2025-02-03 09:44:40'),
('9fknk0m47nhnqvvcs3sphuuvmd', 20250001, '2025-01-28 00:28:46', '2025-01-28 00:28:46'),
('9jf3plaa76mu0r3ao3n2tpt9ir', 20250001, '2025-02-03 13:42:56', '2025-02-03 13:42:56'),
('9k9r3vc43eiqrpd00j6jmrmp8u', 20250001, '2025-01-30 12:28:17', '2025-01-30 12:28:17'),
('9livfq34t7uhgub66afjhqn47c', 20250002, '2025-02-01 14:30:35', '2025-02-01 14:30:35'),
('b2t353gfk0kbj1u54dm2gg2jta', 20250002, '2025-02-01 14:38:31', '2025-02-01 14:38:31'),
('becbibi8c5jiigrpqvp9ul3fof', 20240001, '2025-01-26 08:39:23', '2025-01-26 08:39:23'),
('bs8gdmoued4i23ujsri9dmobpa', 20250003, '2025-02-02 13:25:36', '2025-02-02 13:25:36'),
('c3ag0uoe3g8skdkc3sgii563ab', 20250002, '2025-02-01 15:38:05', '2025-02-01 15:38:05'),
('cjj4bt85n1and3bk5fgq6sf476', 20250002, '2025-02-03 09:55:47', '2025-02-03 09:55:47'),
('cm6idj4mrndm4uakvk5oqasjd7', 20250002, '2025-02-01 14:42:41', '2025-02-01 14:42:41'),
('eaoq1n67tgi06h811b3ip3qg2h', 20250004, '2025-02-03 13:43:03', '2025-02-03 13:43:03'),
('esr4vqd4c003tmgkpqbehv958o', 20250002, '2025-01-26 13:50:36', '2025-01-26 13:50:36'),
('gnpod1qjh1dsetnfhghhvq30ss', 20250002, '2025-02-03 13:29:35', '2025-02-03 13:29:35'),
('h750feufisohqpqsb289lsfan1', 20250002, '2025-02-03 09:59:20', '2025-02-03 09:59:20'),
('hlnrvg5cl6on9ei3cc8hqcl73h', 20250002, '2025-02-01 13:48:12', '2025-02-01 13:48:12'),
('i58d0ut80p6nv3nh1nf4uc4f11', 20250003, '2025-01-29 13:41:42', '2025-01-29 13:41:42'),
('i9ql0hede0dtd5vce1sk4jnqoa', 20250002, '2025-02-03 09:32:54', '2025-02-03 09:32:54'),
('ilb2ecadv5itf9bj8si8ca4aq2', 20240001, '2025-01-26 08:04:07', '2025-01-26 08:04:07'),
('jtk4gqq8vcnnfvoa08gqpok8ur', 20240003, '2025-01-26 07:57:42', '2025-01-26 07:57:42'),
('juf8pn5ur0m83eg92khdlo0l3i', 20250002, '2025-02-03 13:39:29', '2025-02-03 13:39:29'),
('k1i2fstgvpvhe5j6dsbojvme4m', 20250002, '2025-02-02 12:37:12', '2025-02-02 12:37:12'),
('k1nf4acbsmfjti9c5b8kmvvq9m', 20250002, '2025-02-02 12:42:53', '2025-02-02 12:42:53'),
('lgsql0puqu1pvibkn9j6f9p35h', 20250001, '2025-01-26 13:52:26', '2025-01-26 13:52:26'),
('mtvss46r8m2ubkjct6j574f646', 20250001, '2025-02-01 15:33:05', '2025-02-01 15:33:05'),
('n1tean9t4qkibthvh7kp9kjrgp', 20250001, '2025-02-02 12:43:02', '2025-02-02 12:43:02'),
('n29st7hd15iqht2nkp3h3tdl93', 20250001, '2025-02-03 13:03:13', '2025-02-03 13:03:13'),
('n8pnhk22ipitrevor9irr1v17u', 20250002, '2025-02-03 10:31:19', '2025-02-03 10:31:19'),
('oancb9rpkuii6isptq9sum5c5u', 20250002, '2025-01-30 12:33:46', '2025-01-30 12:33:46'),
('olsou235sa22asibdn9al12frb', 20250003, '2025-02-03 13:47:24', '2025-02-03 13:47:24'),
('oma9dkgbao1c735a4f90rnnkkr', 20240004, '2025-01-26 07:58:39', '2025-01-26 07:58:39'),
('pf3cb3diuvr4vvgq2fa8s7pdmo', 20250003, '2025-02-01 13:52:29', '2025-02-01 13:52:29'),
('ptbkjdltvq0a02j0k42eu1pr2e', 20240003, '2025-01-26 09:11:16', '2025-01-26 09:11:16'),
('q59oioubca9v29or23mkdk7dnr', 20250005, '2025-02-03 10:33:25', '2025-02-03 10:33:25'),
('r30r6p44i6ob567v26q9fsg3rl', 20250001, '2025-02-03 08:06:12', '2025-02-03 08:06:12'),
('rvjtrl5u9gn7udkq5be03kdgq5', 20250001, '2025-02-03 10:20:35', '2025-02-03 10:20:35'),
('sc4dnfrl7q6avrvaocptrmlaeb', 20240004, '2025-01-26 09:40:26', '2025-01-26 09:40:26'),
('t7v7rt1fvv2q3qv4s0p1pu79nq', 20250002, '2025-02-03 09:12:26', '2025-02-03 09:12:26'),
('uv5kq29csmge57elv37ocrje0b', 20250002, '2025-02-01 14:23:08', '2025-02-01 14:23:08'),
('vc161bcem6qiupn18pcv0k5129', 20250002, '2025-02-01 14:39:36', '2025-02-01 14:39:36');

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
('20250006', 'receptionist3', '$2y$10$n58FsM5GgS9CQb1GwJoyCeZKIZm9NDrK/D5ZDkRwRfw2gHb296XHi', 'Receptionist', '', '', '0', '2025-01-28 00:28:59');

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
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `failed_logins`
--
ALTER TABLE `failed_logins`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_username` (`username`);

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
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=44;

--
-- AUTO_INCREMENT for table `failed_logins`
--
ALTER TABLE `failed_logins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
