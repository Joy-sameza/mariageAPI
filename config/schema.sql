-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Feb 08, 2024 at 02:53 PM
-- Server version: 10.6.14-MariaDB-cll-lve
-- PHP Version: 7.2.34

CREATE DATABASE IF NOT EXISTS `u812056030_mariage` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `u812056030_mariage`;

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `u812056030_mariage`
--

-- --------------------------------------------------------

--
-- Table structure for table `administrator`
--

CREATE TABLE `administrator` (
  `id` int(11) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `password` varchar(255) NOT NULL,
  `telephone` varchar(14) NOT NULL,
  `name` varchar(50) NOT NULL,
  `actual_name` varchar(100) NOT NULL,
  `archived` bit(1) NOT NULL DEFAULT b'0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- --------------------------------------------------------

--
-- Table structure for table `invitee`
--

CREATE TABLE `invitee` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `actual_name` varchar(255) NOT NULL,
  `table_number` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `admin_ref` int(11) NOT NULL,
  `telephone` varchar(15) DEFAULT NULL,
  `archived` bit(1) NOT NULL DEFAULT b'0',
  `present` bit(1) NOT NULL DEFAULT b'0',
  `is_out` bit(1) NOT NULL DEFAULT b'0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `telephone` varchar(14) NOT NULL,
  `actual_name` varchar(100) NOT NULL,
  `admin_ref` int(11) NOT NULL,
  `password_modified` bit(1) NOT NULL DEFAULT b'0',
  `archived` bit(1) NOT NULL DEFAULT b'0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `administrator`
--
ALTER TABLE `administrator`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`) USING BTREE,
  ADD KEY `actual_name` (`actual_name`),
  ADD KEY `password` (`password`),
  ADD KEY `telephone` (`telephone`),
  ADD KEY `archived` (`archived`),
  ADD KEY `created_at` (`created_at`),
  ADD KEY `administrator_idx` (`actual_name`,`archived`,`created_at`,`id`,`name`,`password`,`telephone`);

--
-- Indexes for table `invitee`
--
ALTER TABLE `invitee`
  ADD PRIMARY KEY (`id`),
  ADD KEY `invitee_ibfk_1` (`admin_ref`),
  ADD KEY `invitee_ibfk_2` (`archived`),
  ADD KEY `actual_name` (`actual_name`),
  ADD KEY `table_number` (`table_number`),
  ADD KEY `telephone` (`telephone`),
  ADD KEY `is_out` (`is_out`),
  ADD KEY `present` (`present`),
  ADD KEY `invitee_idx` (`id`,`actual_name`,`table_number`,`admin_ref`,`telephone`,`archived`,`present`,`is_out`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`),
  ADD KEY `fk_admin_ref` (`admin_ref`),
  ADD KEY `actual_name` (`actual_name`),
  ADD KEY `telephone` (`telephone`),
  ADD KEY `password` (`password`) USING BTREE,
  ADD KEY `password_modified` (`password_modified`),
  ADD KEY `auth.users_ibfk_1` (`archived`),
  ADD KEY `users_idx` (`id`,`name`,`password`,`telephone`,`actual_name`,`admin_ref`,`password_modified`,`archived`) USING BTREE;

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `administrator`
--
ALTER TABLE `administrator`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=43;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `invitee`
--
ALTER TABLE `invitee`
  ADD CONSTRAINT `invitee_ibfk_1` FOREIGN KEY (`admin_ref`) REFERENCES `administrator` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `invitee_ibfk_2` FOREIGN KEY (`archived`) REFERENCES `administrator` (`archived`) ON UPDATE CASCADE;

--
-- Constraints for table `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `auth.users_ibfk_1` FOREIGN KEY (`archived`) REFERENCES `administrator` (`archived`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_admin_ref` FOREIGN KEY (`admin_ref`) REFERENCES `administrator` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
